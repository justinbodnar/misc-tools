import dns.resolver
import time
import argparse

txt = "domain-mx-checker-input.txt"

# Setup DNS resolver
resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8', '1.1.1.1']
resolver.timeout = 5
resolver.lifetime = 10

VERBOSE = False

def check_dns_record(name, record_type, subdomain=''):
    query = f"{subdomain}.{name}" if subdomain else name
    for attempt in range(3):
        try:
            answers = resolver.resolve(query, record_type, raise_on_no_answer=False)
            results = [r.to_text() for r in answers]
            if VERBOSE:
                print(f"[VERBOSE] {record_type} record for {query}: {results}")
            return results
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            if VERBOSE:
                print(f"[VERBOSE] {record_type} record for {query}: No Answer")
            return []
        except (dns.resolver.Timeout, dns.resolver.LifetimeTimeout):
            if VERBOSE:
                print(f"[VERBOSE] {record_type} record for {query}: Timeout (attempt {attempt+1})")
            time.sleep(1)
    return []

def get_dmarc(domain):
    # 1) Proper DMARC host
    d = check_dns_record(domain, 'TXT', '_dmarc')
    # 2) Mis-configured “double” host
    if not d:
        d = check_dns_record(domain, 'TXT', f'_dmarc.{domain}')
        if VERBOSE and d:
            print(f"[VERBOSE] Found DMARC under mis-host _dmarc.{domain}.{domain}")
    # 3) Fallback: scan apex TXT
    if not d:
        apex = check_dns_record(domain, 'TXT')
        if VERBOSE:
            print(f"[VERBOSE] Apex TXT for {domain}: {apex}")
        return [r for r in apex if 'v=DMARC1' in r] or None
    return [r for r in d if 'v=DMARC1' in r] or None

def get_dkim(domain):
    selectors = ['selector1','selector2','google','default','smtp','mail','dkim','mx'] \
                + [f"selector{i}" for i in range(1,11)]
    recs = []
    for sel in selectors:
        recs += check_dns_record(domain, 'TXT', f'{sel}._domainkey')
    return recs or None

def guess_spf_include(mx_records):
    includes = set()
    if not mx_records:
        return None
    for mx in mx_records:
        parts = mx.split()
        if len(parts)==2:
            t = parts[1].rstrip('.').lower()
            if 'outlook.com' in t:        includes.add('include:spf.protection.outlook.com')
            elif 'google.com' in t:       includes.add('include:_spf.google.com')
            elif 'zoho' in t:             includes.add('include:zoho.eu')
            elif 'protonmail' in t:       includes.add('include:spf.protonmail.ch')
            elif 'secureserver.net' in t: includes.add('include:secureserver.net')
            elif 'emailsrvr.com' in t:    includes.add('include:emailsrvr.com')
            elif 'mailgun.org' in t:      includes.add('include:mailgun.org')
            elif 'sendgrid.net' in t:     includes.add('include:sendgrid.net')
            else:                         includes.add('include:<your-provider>')
    return ' '.join(includes)

def build_dmarc(domain, has_mx):
    return '_dmarc IN TXT "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;"'

def analyze_domain(domain):
    res = {'domain': domain}
    res['MX']    = check_dns_record(domain, 'MX') or None
    txts        = check_dns_record(domain, 'TXT')
    res['SPF']   = [r for r in txts if r.startswith('"v=spf1')] or None
    res['DMARC'] = get_dmarc(domain)
    res['DKIM']  = get_dkim(domain) if res['MX'] else "N/A"
    return res

def main():
    global VERBOSE
    parser = argparse.ArgumentParser()
    parser.add_argument('-v','--verbose', action='store_true')
    args = parser.parse_args()
    VERBOSE = args.verbose

    domains = [d.strip() for d in open(txt) if d.strip()]
    missing_spf, missing_dkim, missing_dmarc = {}, [], []
    fully_protected = []

    print("\n=== Checking Domains ===\n")
    for i, d in enumerate(domains, start=1):
        print(f"[{i}/{len(domains)}] Checking {d}...")
        r = analyze_domain(d)

        has_mx    = bool(r['MX'])
        has_spf   = bool(r['SPF'])
        has_dmarc = bool(r['DMARC'])
        has_dkim  = (r['DKIM']=="N/A") or bool(r['DKIM'])

        print(f"  Email Setup (MX): {'YES' if has_mx else 'NO'}")
        print(f"  SPF: {'Found' if has_spf else 'Not Found'}")
        print(f"  MX records: {r['MX']}")  # <<-- ADDED LINE
        print(f"  DMARC: {'Found' if has_dmarc else 'Not Found'}")
        print(f"  DKIM: { 'N/A' if r['DKIM']=='N/A' else ('Found' if has_dkim else 'Not Found')}")

        prefix = "[MX] " if has_mx else ""
        # track missing
        if not has_spf:
            inc = guess_spf_include(r['MX']) if has_mx else None
            missing_spf[f"{prefix}{d}"] = f'@ IN TXT "v=spf1 {inc or "-all"} -all"'
        if has_mx and not has_dkim:
            missing_dkim.append(f"{prefix}{d}")
        if not has_dmarc:
            missing_dmarc.append((f"{prefix}{d}", build_dmarc(d, has_mx)))

        # track fully protected
        if has_spf and has_dmarc and (not has_mx or has_dkim):
            fully_protected.append(f"{prefix}{d}")

    # missing lists
    print("\n=== DOMAINS MISSING SPF ===")
    for d, rec in missing_spf.items():
        print(f" - {d}\n    {rec}")

    print("\n=== DOMAINS MISSING DKIM (MX only) ===")
    for d in missing_dkim:
        print(f" - {d}")

    print("\n=== DOMAINS MISSING DMARC ===")
    for d, rec in missing_dmarc:
        print(f" - {d}\n    {rec}")

    # **new** fully protected list
    print("\n=== FULLY PROTECTED DOMAINS ===")
    if fully_protected:
        for d in fully_protected:
            print(f" - {d}")
    else:
        print(" (none)")

    # action plan
    print("\n=== ACTION PLAN ===")
    print("\nFor domains WITHOUT email service (no MX), add:")
    print('    @ IN TXT "v=spf1 -all"')
    print('    _dmarc IN TXT "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;"')
    print("    (No DKIM needed)")

    print("\nFor domains WITH email service (MX found), add:")
    print('    @ IN TXT "v=spf1 include:<your provider> -all"')
    print('    _dmarc IN TXT "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;"')
    print('    DKIM via your email provider (e.g., Microsoft, Google)')

    print("\n✅ Fully Protected = SPF + DKIM (if email) + DMARC.\n")

if __name__=='__main__':
    main()

