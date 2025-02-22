import argparse
import asyncio
import httpx
import aiodns
import csv
import multiprocessing
from concurrent.futures import ThreadPoolExecutor

# Services that are vulnerable to takeover
TAKEOVER_SERVICES = ["github.io", "herokuapp.com", "netlify.app", "readthedocs.io", "azurewebsites.net", "surge.sh"]

# Async DNS resolver
resolver = aiodns.DNSResolver()

async def get_status(client, domain):
    try:
        response = await client.get(f"http://{domain}", timeout=5)
        return response.status_code
    except:
        return None

async def get_cname(domain):
    try:
        result = await resolver.query(domain, "CNAME")
        return [r.host for r in result]
    except:
        return None

async def check_takeover(domain, client, hide):
    status_code = await get_status(client, domain)
    cname_records = await get_cname(domain)

    if status_code == 404 and cname_records:
        for cname in cname_records:
            for service in TAKEOVER_SERVICES:
                if service in cname:
                    if hide:
                        print(f"[🔥] {domain} -> {cname} (Possible Takeover!)")
                    else:
                        print(f"[🔥] {domain} -> {cname} | Status: {status_code} | Possible Takeover: Yes")
                    return {"Domain": domain, "CNAME": cname, "Status": status_code, "Possible Takeover": "Yes"}

    if not hide:
        print(f"[ℹ️] {domain} -> CNAME: {cname_records} | Status: {status_code} | Possible Takeover: No")

    return {"Domain": domain, "CNAME": cname_records, "Status": status_code, "Possible Takeover": "No"}

async def process_domains_async(domains, hide):
    tasks = []
    async with httpx.AsyncClient(timeout=5, follow_redirects=True) as client:
        for domain in domains:
            tasks.append(check_takeover(domain, client, hide))

        return await asyncio.gather(*tasks)

def process_domains_worker(domain_chunk, hide):
    """Runs in a separate process"""
    return asyncio.run(process_domains_async(domain_chunk, hide))

def save_results(results, filename):
    with open(filename, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["Domain", "CNAME", "Status", "Possible Takeover"])
        writer.writeheader()
        writer.writerows(results)
    print(f"[✔] Results saved to {filename}")

def chunk_list(lst, n):
    """Split list into n equal chunks"""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def load_domains(filename):
    with open(filename, "r") as file:
        return [line.strip() for line in file.readlines()]

def main():
    parser = argparse.ArgumentParser(description="Massive 404 Subdomain Takeover Scanner")
    parser.add_argument("-l", "--list", required=True, help="File containing list of URLs")
    parser.add_argument("-o", "--output", help="Save results to a file")
    parser.add_argument("--hide", action="store_true", help="Show only vulnerable domains")
    parser.add_argument("--workers", type=int, default=10000, help="Number of parallel workers")

    args = parser.parse_args()
    domains = load_domains(args.list)

    print(f"[🚀] Scanning {len(domains)} domains using {args.workers} workers...")

    # Split domains for multiprocessing
    num_cores = multiprocessing.cpu_count()
    chunk_size = max(1, len(domains) // num_cores)
    domain_chunks = list(chunk_list(domains, chunk_size))

    # Run multiprocessing
    with multiprocessing.Pool(processes=num_cores) as pool:
        results = pool.starmap(process_domains_worker, [(chunk, args.hide) for chunk in domain_chunks])

    # Flatten results
    results = [item for sublist in results for item in sublist if item]

    if args.output:
        save_results(results, args.output)

if __name__ == "__main__":
    main()
