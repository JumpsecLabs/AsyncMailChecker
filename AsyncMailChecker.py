#!/usr/bin/env python3
"""
Ultimate Asynchronous Email Checker
  
Dependencies:
  pip install streamlit aiodns pandas altair setuptools

Tested on python3.11.9
"""

import streamlit as st
import pandas as pd
import altair as alt
import io, os, re, time, asyncio, aiodns
from datetime import datetime

# Global DNS cache (key: (name, record_type), value: list of TXT strings)
_dns_cache = {}

# --- Async DNS Query with Caching and Controlled Concurrency ---
async def async_query_txt_records(name: str, record_type="TXT", verbose=False,
                                  dns_timeout=2, dns_retries=3, resolver=None, semaphore=None):
    key = (name, record_type)
    if key in _dns_cache:
        return _dns_cache[key]
    results = []
    for attempt in range(dns_retries):
        try:
            async with semaphore:
                response = await resolver.query(name, record_type)
            for r in response:
                results.append("".join(r.text))
            break
        except Exception as e:
            if verbose:
                st.write(f"DEBUG: Attempt {attempt+1} failed for {name} -> {e}")
            if attempt == dns_retries - 1:
                pass
    _dns_cache[key] = results
    return results

# --- SPF-related functions ---
def extract_spf_mechanisms(spf_string: str):
    tokens = spf_string.split()
    results = []
    for t in tokens:
        low = t.lower()
        if low.startswith("v=spf1"):
            continue
        if any(low.startswith(prefix) for prefix in [
            "ip4:", "ip6:", "include:", "redirect=", "exp=", "exists:",
            "ptr", "a", "mx"
        ]):
            results.append(t)
        elif "all" in low:
            results.append(t)
    return results

async def async_parse_spf_record(domain: str, verbose=False, level=0, max_level=2,
                                  visited=None, dns_timeout=2, dns_retries=3,
                                  resolver=None, semaphore=None):
    if visited is None:
        visited = set()
    results = []
    if domain in visited:
        return results
    visited.add(domain)
    txts = await async_query_txt_records(domain, verbose=verbose,
                                          dns_timeout=dns_timeout, dns_retries=dns_retries,
                                          resolver=resolver, semaphore=semaphore)
    spf_rec = None
    for t in txts:
        if "v=spf1" in t.lower():
            spf_rec = t
            break
    if not spf_rec:
        return results
    mechs = extract_spf_mechanisms(spf_rec)
    for m in mechs:
        results.append((domain, m))
    if level < max_level:
        for m in mechs:
            low = m.lower()
            if low.startswith("include:"):
                incl_dom = m.split(":", 1)[1]
                sub_res = await async_parse_spf_record(incl_dom, verbose=verbose, level=level+1,
                                                        max_level=max_level, visited=visited,
                                                        dns_timeout=dns_timeout, dns_retries=dns_retries,
                                                        resolver=resolver, semaphore=semaphore)
                results.extend(sub_res)
            elif low.startswith("redirect="):
                red_dom = m.split("=", 1)[1]
                sub_res = await async_parse_spf_record(red_dom, verbose=verbose, level=level+1,
                                                        max_level=max_level, visited=visited,
                                                        dns_timeout=dns_timeout, dns_retries=dns_retries,
                                                        resolver=resolver, semaphore=semaphore)
                results.extend(sub_res)
    return results

async def async_check_spf_bool_only(domain: str, verbose=False, dns_timeout=2,
                                    dns_retries=3, resolver=None, semaphore=None) -> bool:
    txts = await async_query_txt_records(domain, verbose=verbose, dns_timeout=dns_timeout,
                                         dns_retries=dns_retries, resolver=resolver, semaphore=semaphore)
    for t in txts:
        if "v=spf1" in t.lower():
            return True
    return False

# --- DMARC-related functions ---
def parse_dmarc_policy(txt: str) -> str:
    match = re.search(r"(?i)\bp\s*=\s*(none|quarantine|reject)\b", txt)
    return match.group(1).lower() if match else "unknown"

def parse_dmarc_fo(txt: str) -> str:
    match = re.search(r"(?i)\bfo\s*=\s*([0-1ds:]+)\b", txt)
    return match.group(1).lower() if match else "not-found"

def parse_dmarc_rua(txt: str) -> str:
    match = re.search(r"(?i)\brua\s*=\s*([^;\s]+)", txt)
    return match.group(1) if match else "none"

def parse_dmarc_ruf(txt: str) -> str:
    match = re.search(r"(?i)\bruf\s*=\s*([^;\s]+)", txt)
    return match.group(1) if match else "none"

def parse_dmarc_adkim(txt: str) -> str:
    match = re.search(r"(?i)\badkim\s*=\s*([sr])\b", txt)
    return match.group(1).lower() if match else "r"

def parse_dmarc_aspf(txt: str) -> str:
    match = re.search(r"(?i)\baspf\s*=\s*([sr])\b", txt)
    return match.group(1).lower() if match else "r"

async def async_check_dmarc_subdomain(domain: str, verbose=False, dns_timeout=2,
                                      dns_retries=3, resolver=None, semaphore=None):
    txts = await async_query_txt_records(f"_dmarc.{domain}", verbose=verbose,
                                          dns_timeout=dns_timeout, dns_retries=dns_retries,
                                          resolver=resolver, semaphore=semaphore)
    if not txts:
        return (False, "no-record", "not-found", "none", "none", "r", "r")
    for t in txts:
        if "v=dmarc1" in t.lower():
            p_val = parse_dmarc_policy(t)
            fo_val = parse_dmarc_fo(t)
            rua_val = parse_dmarc_rua(t)
            ruf_val = parse_dmarc_ruf(t)
            adkim_val = parse_dmarc_adkim(t)
            aspf_val = parse_dmarc_aspf(t)
            rua_val = rua_val.replace("mailto:", "")
            ruf_val = ruf_val.replace("mailto:", "")
            return (True, p_val, fo_val, rua_val, ruf_val, adkim_val, aspf_val)
    return (False, "no-record", "not-found", "none", "none", "r", "r")

async def async_check_dmarc_bruteforce(domain: str, verbose=False, dns_timeout=2,
                                      dns_retries=3, resolver=None, semaphore=None):
    common_subs = ["", "www", "mail", "smtp", "email"]
    for sub in common_subs:
        full_dom = f"{sub}.{domain}" if sub else domain
        if verbose:
            st.write(f"DMARC subdomain check: _dmarc.{full_dom}")
        found, p_val, fo_val, rua_val, ruf_val, adkim_val, aspf_val = \
            await async_check_dmarc_subdomain(full_dom, verbose=verbose, dns_timeout=dns_timeout,
                                              dns_retries=dns_retries, resolver=resolver, semaphore=semaphore)
        if found:
            return (True, sub, p_val, fo_val, rua_val, ruf_val, adkim_val, aspf_val)
    return (False, "", "no-record", "not-found", "none", "none", "r", "r")

# --- DKIM-related function ---
COMMON_DKIM_SELECTORS = [
    "default", "mail", "selector1", "selector2",
    "google", "amazonses", "dkim", "smtp",
    "k1", "s1"
]

async def async_check_dkim(domain: str, verbose=False, dns_timeout=2,
                           dns_retries=3, resolver=None, semaphore=None) -> bool:
    if verbose:
        st.write(f"Checking DKIM for {domain}")
    for sel in COMMON_DKIM_SELECTORS:
        sub = f"{sel}._domainkey.{domain}"
        txts = await async_query_txt_records(sub, verbose=verbose, dns_timeout=dns_timeout,
                                             dns_retries=dns_retries, resolver=resolver, semaphore=semaphore)
        for t in txts:
            if "v=dkim1" in t.lower():
                return True
    return False

# --- Combined Domain Check (Async) ---
async def async_check_domain(domain, spf_depth, verbose, dns_timeout, dns_retries,
                             resolver, semaphore):
    try:
        spf_ok = await async_check_spf_bool_only(domain, verbose=verbose,
                                                 dns_timeout=dns_timeout, dns_retries=dns_retries,
                                                 resolver=resolver, semaphore=semaphore)
        spf_mechs = []
        spf_hosts = ""
        spf_hosts_source = ""
        if spf_depth > 0:
            spf_mechs = await async_parse_spf_record(domain, verbose=verbose, max_level=spf_depth,
                                                     dns_timeout=dns_timeout, dns_retries=dns_retries,
                                                     resolver=resolver, semaphore=semaphore)
            flatten = []
            lines = []
            for (src_d, mech_s) in spf_mechs:
                flatten.append(mech_s)
                lines.append(f"{src_d} => {mech_s}")
            spf_hosts = ", ".join(flatten)
            spf_hosts_source = "\n".join(lines)
        dkim_ok = await async_check_dkim(domain, verbose=verbose,
                                         dns_timeout=dns_timeout, dns_retries=dns_retries,
                                         resolver=resolver, semaphore=semaphore)
        found, sub_used, p_val, fo_val, rua_val, ruf_val, adkim_val, aspf_val = \
            await async_check_dmarc_bruteforce(domain, verbose=verbose,
                                               dns_timeout=dns_timeout, dns_retries=dns_retries,
                                               resolver=resolver, semaphore=semaphore)
        dmarc_ok = found
        return {
            "domain": domain,
            "spf": spf_ok,
            "dkim": dkim_ok,
            "dmarc": dmarc_ok,
            "dmarc_subdomain": sub_used,
            "dmarc_policy": p_val,
            "dmarc_fo": fo_val,
            "dmarc_rua": rua_val,
            "dmarc_ruf": ruf_val,
            "dmarc_adkim": adkim_val,
            "dmarc_aspf": aspf_val,
            "spf_hosts": spf_hosts,
            "spf_hosts_source": spf_hosts_source,
        }
    except Exception as e:
        if verbose:
            st.write(f"Error processing {domain}: {e}")
        return {
            "domain": domain,
            "spf": False,
            "dkim": False,
            "dmarc": False,
            "dmarc_subdomain": "",
            "dmarc_policy": "",
            "dmarc_fo": "",
            "dmarc_rua": "",
            "dmarc_ruf": "",
            "dmarc_adkim": "",
            "dmarc_aspf": "",
            "spf_hosts": "",
            "spf_hosts_source": "",
        }

# --- Async Runner for DNS Checks ---
async def run_checks(domains, spf_depth, verbose, dns_timeout, dns_retries, resolver, semaphore, progress_callback):
    results = []
    total = len(domains)
    completed = 0
    tasks = [async_check_domain(dom, spf_depth, verbose, dns_timeout, dns_retries, resolver, semaphore) for dom in domains]
    for coro in asyncio.as_completed(tasks):
        result = await coro
        results.append(result)
        completed += 1
        progress_callback(result["domain"], completed, total)
    return results

# --- show_logo ---
def show_logo():
    st.image("logo.png", use_container_width=False)

# --- Main App (Async) ---
def main():
    show_logo()
    st.title("Asynchronous Email Checker")
    # Sidebar settings
    verbose = st.sidebar.checkbox("Verbose Logging", value=False)
    generate_csv = st.sidebar.checkbox("Generate CSV (Save Session)", value=False)
    store_historical = st.sidebar.checkbox("Store Aggregated Stats", value=False)
    spf_depth = st.sidebar.slider("SPF recursion depth", 0, 4, 2)
    dns_timeout = st.sidebar.slider("DNS Timeout (seconds)", 1.0, 10.0, 2.0, step=0.5)
    dns_retries = st.sidebar.slider("DNS Retries", 1, 10, 3)
    max_concurrent = st.sidebar.slider("Max Concurrent DNS Queries", 1, 50, 10)
    nameserver = st.sidebar.text_input("DNS Nameserver", value="8.8.8.8")
    
    st.sidebar.header("Load or Scan Data")
    load_results_option = st.sidebar.radio("Choose Action", ["Scan New Data","Load Saved Results"], index=0)
    st.sidebar.header("Chart Settings")
    show_matrix = st.sidebar.checkbox("Presence Matrix", value=True)
    show_chart_grouped = st.sidebar.checkbox("Grouped Bar", value=False)
    show_chart_policy = st.sidebar.checkbox("DMARC Policy", value=False)
    show_chart_fo = st.sidebar.checkbox("DMARC FO", value=False)
    show_chart_rua = st.sidebar.checkbox("DMARC RUA", value=False)
    show_chart_combos = st.sidebar.checkbox("Combos & Donut", value=False)
    show_chart_history = st.sidebar.checkbox("Historical Timeline", value=False)
    
    if "expand_all_summaries" not in st.session_state:
        st.session_state["expand_all_summaries"] = True
    def toggle_expand():
        st.session_state["expand_all_summaries"] = not st.session_state["expand_all_summaries"]
    st.button("Expand/Collapse All", on_click=toggle_expand)
    
    df = st.session_state.get("df", None)
    if load_results_option == "Load Saved Results":
        st.info("Load previously saved CSV results.")
        loaded_file = st.file_uploader("Select CSV from previous run", type=["csv"])
        if loaded_file:
            df = pd.read_csv(loaded_file)
            st.success("Loaded results from file!")
            st.session_state["df"] = df
    else:
        uploaded_file = st.file_uploader("Upload a .txt domain list", type=["txt"])
        if uploaded_file is not None:
            if st.button("Run DNS Checks"):
                domains = uploaded_file.read().decode("utf-8").splitlines()
                domains = [d.strip() for d in domains if d.strip()]
                if not domains:
                    st.error("No domains found in file.")
                    return
                st.info(f"Processing {len(domains)} domains asynchronously (SPF depth={spf_depth}).")
                
                progress_bar = st.progress(0)
                progress_label = st.empty()
                total = len(domains)
                def progress_callback(domain, completed, total):
                    progress_label.text(f"Domain Checked: {domain} ({completed}/{total})")
                    progress_bar.progress(int(completed/total*100))
                
                # Create a new event loop and set it for this thread, then pass it to the resolver
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                resolver = aiodns.DNSResolver(loop=loop, nameservers=[nameserver], timeout=dns_timeout)
                semaphore = asyncio.Semaphore(max_concurrent)
                
                results = loop.run_until_complete(
                    run_checks(domains, spf_depth, verbose, dns_timeout, dns_retries,
                               resolver, semaphore, progress_callback)
                )
                loop.close()
                
                st.success("All DNS checks done!")
                progress_bar.empty()
                progress_label.empty()
                df = pd.DataFrame(results)
                st.session_state["df"] = df
                
                if generate_csv:
                    csv_buf = io.StringIO()
                    csv_buf.write("Domain,SPF,DKIM,DMARC,Subdomain,Policy,FO,RUA,RUF,adkim,aspf,SPF_Hosts,SPF_Hosts_Source\n")
                    for row in results:
                        dom = row["domain"]
                        spf_ok = "Yes" if row["spf"] else "No"
                        dkim_ok = "Yes" if row["dkim"] else "No"
                        dmarc_ok = "Yes" if row["dmarc"] else "No"
                        sub_d = row["dmarc_subdomain"]
                        p_val = row["dmarc_policy"]
                        fo_val = row["dmarc_fo"]
                        rua_val = row["dmarc_rua"]
                        ruf_val = row["dmarc_ruf"]
                        adkim_val = row["dmarc_adkim"]
                        aspf_val = row["dmarc_aspf"]
                        spf_hosts = row["spf_hosts"]
                        spf_source = row["spf_hosts_source"].replace('"','""')
                        csv_buf.write(f"{dom},{spf_ok},{dkim_ok},{dmarc_ok},{sub_d},{p_val},{fo_val},{rua_val},{ruf_val},{adkim_val},{aspf_val},\"{spf_hosts}\",\"{spf_source}\"\n")
                    st.write("Download current results CSV:")
                    st.download_button("Download CSV", data=csv_buf.getvalue().encode("utf-8"),
                                       file_name="dns_checker_results.csv", mime="text/csv")
                if store_historical:
                    missing_spf_list, missing_dkim_list, missing_dmarc_list = [], [], []
                    valid_list = []
                    for row in results:
                        if not row["spf"]:
                            missing_spf_list.append(row["domain"])
                        if not row["dkim"]:
                            missing_dkim_list.append(row["domain"])
                        if not row["dmarc"]:
                            missing_dmarc_list.append(row["domain"])
                        if row["spf"] and row["dkim"] and row["dmarc"]:
                            valid_list.append(row["domain"])
                    run_date = datetime.now().strftime("%Y-%m-%d")
                    newrow = {
                        "date": run_date,
                        "total_domains": len(domains),
                        "fully_protected": len(valid_list),
                        "missing_spf": len(missing_spf_list),
                        "missing_dkim": len(missing_dkim_list),
                        "missing_dmarc": len(missing_dmarc_list),
                    }
                    if os.path.exists("historical_data.csv"):
                        df_history = pd.read_csv("historical_data.csv")
                    else:
                        df_history = pd.DataFrame(columns=["date","total_domains","fully_protected","missing_spf","missing_dkim","missing_dmarc"])
                    df_history = pd.concat([df_history, pd.DataFrame([newrow])], ignore_index=True)
                    df_history.to_csv("historical_data.csv", index=False)
                    st.success("Appended aggregated stats to historical_data.csv")
        else:
            st.info("Upload .txt domain list to begin scanning.")
    
    if df is None or df.empty:
        st.warning("No data loaded or scanned yet.")
        return

    # --- Display the Matrix once above the Textual Summaries ---
    st.subheader("Records Matrix")
    st.dataframe(df)
    
    # --- Textual Summaries ---
    st.header("Summary")
    total_n = len(df)
    missing_spf_list = df.loc[~df["spf"], "domain"].tolist()
    missing_dkim_list = df.loc[~df["dkim"], "domain"].tolist()
    missing_dmarc_list = df.loc[~df["dmarc"], "domain"].tolist()
    valid_domains = []
    missing_all_list = []
    missing_spf_dkim_list = []
    missing_spf_dmarc_list = []
    missing_dmarc_dkim_list = []
    for idx, row in df.iterrows():
        dom = row["domain"]
        spf_m = not row["spf"]
        dkim_m = not row["dkim"]
        dmarc_m = not row["dmarc"]
        if spf_m and dkim_m and dmarc_m:
            missing_all_list.append(dom)
        elif spf_m and dkim_m:
            missing_spf_dkim_list.append(dom)
        elif spf_m and dmarc_m:
            missing_spf_dmarc_list.append(dom)
        elif dkim_m and dmarc_m:
            missing_dmarc_dkim_list.append(dom)
        elif not spf_m and not dkim_m and not dmarc_m:
            valid_domains.append(dom)
    
    expand = st.session_state["expand_all_summaries"]
    with st.expander("Domains with all protections", expanded=expand):
        st.success(f"Domains with all protections: {len(valid_domains)}/{total_n}")
        st.code("\n".join(valid_domains))
    with st.expander("Missing SPF", expanded=expand):
        st.warning(f"Domains missing SPF: {len(missing_spf_list)}/{total_n}")
        st.code("\n".join(missing_spf_list))
    with st.expander("Missing DKIM", expanded=expand):
        st.warning(f"Domains missing DKIM: {len(missing_dkim_list)}/{total_n}")
        st.code("\n".join(missing_dkim_list))
    with st.expander("Missing DMARC", expanded=expand):
        st.warning(f"Domains missing DMARC: {len(missing_dmarc_list)}/{total_n}")
        st.code("\n".join(missing_dmarc_list))
    with st.expander("Missing SPF+DKIM", expanded=expand):
        st.error(f"Domains missing SPF and DKIM: {len(missing_spf_dkim_list)}/{total_n}")
        st.code("\n".join(missing_spf_dkim_list))
    with st.expander("Missing SPF+DMARC", expanded=expand):
        st.error(f"Domains missing SPF and DMARC: {len(missing_spf_dmarc_list)}/{total_n}")
        st.code("\n".join(missing_spf_dmarc_list))
    with st.expander("Missing DKIM+DMARC", expanded=expand):
        st.error(f"Domains missing DKIM and DMARC: {len(missing_dmarc_dkim_list)}/{total_n}")
        st.code("\n".join(missing_dmarc_dkim_list))
    missing_all_count = len(missing_all_list)
    with st.expander("Missing All Three", expanded=expand):
        st.error(f"Domains missing SPF, DKIM, and DMARC: {missing_all_count}/{total_n}")
        st.code("\n".join(missing_all_list))
    
    # Additional textual summaries for SPF hosts information
    spf_hosts_summary = df.loc[df["spf_hosts"] != "", ["domain", "spf_hosts"]]
    if not spf_hosts_summary.empty:
        with st.expander("SPF Hosts", expanded=expand):
            for idx, row in spf_hosts_summary.iterrows():
                st.write(f"{row['domain']}: {row['spf_hosts']}")
    
    spf_hosts_source_summary = df.loc[df["spf_hosts_source"] != "", ["domain", "spf_hosts_source"]]
    if not spf_hosts_source_summary.empty:
        with st.expander("SPF Hosts Source", expanded=expand):
            for idx, row in spf_hosts_source_summary.iterrows():
                st.write(f"{row['domain']}:")
                st.code(row['spf_hosts_source'])
    
    # --- Charts ---
    st.subheader("Charts")
    if show_matrix:
        st.markdown("**Records Matrix:** See the section above the Summary.")
    if show_chart_grouped:
        spf_ok_list = df.loc[df["spf"], "domain"].tolist()
        spf_missing_list = df.loc[~df["spf"], "domain"].tolist()
        dmarc_ok_list = df.loc[df["dmarc"], "domain"].tolist()
        dmarc_missing_list = df.loc[~df["dmarc"], "domain"].tolist()
        dkim_ok_list = df.loc[df["dkim"], "domain"].tolist()
        dkim_missing_list = df.loc[~df["dkim"], "domain"].tolist()
        grouped_data = pd.DataFrame([
            {"record": "SPF", "status": "Present", "domain_count": len(spf_ok_list), "domains": "\n".join(spf_ok_list)},
            {"record": "SPF", "status": "Missing", "domain_count": len(spf_missing_list), "domains": "\n".join(spf_missing_list)},
            {"record": "DMARC", "status": "Present", "domain_count": len(dmarc_ok_list), "domains": "\n".join(dmarc_ok_list)},
            {"record": "DMARC", "status": "Missing", "domain_count": len(dmarc_missing_list), "domains": "\n".join(dmarc_missing_list)},
            {"record": "DKIM", "status": "Present", "domain_count": len(dkim_ok_list), "domains": "\n".join(dkim_ok_list)},
            {"record": "DKIM", "status": "Missing", "domain_count": len(dkim_missing_list), "domains": "\n".join(dkim_missing_list)},
        ])
        chart_grouped = (
            alt.Chart(grouped_data)
            .mark_bar()
            .encode(
                x=alt.X("record:N", title="Record Type"),
                y=alt.Y("domain_count:Q", title="Domains"),
                color="status:N",
                column="status:N",
                tooltip=[
                    alt.Tooltip("domain_count:Q", title="Count"),
                    alt.Tooltip("domains:N", title="Domains"),
                ]
            )
            .properties(width=250, height=400, title="Grouped Bar: SPF / DMARC / DKIM")
        )
        st.altair_chart(chart_grouped, use_container_width=True)
    if show_chart_policy:
        pol_data = df.groupby("dmarc_policy")["domain"].agg(["count", lambda x: "\n".join(x)]).reset_index()
        pol_data.columns = ["dmarc_policy", "domain_count", "domain_list"]
        chart_policy = (
            alt.Chart(pol_data)
            .mark_bar()
            .encode(
                x=alt.X("dmarc_policy:N", sort="-y", title="DMARC Policy"),
                y=alt.Y("domain_count:Q", title="Domains"),
                color=alt.Color("dmarc_policy:N"),
                tooltip=[alt.Tooltip("domain_count:Q", title="Count"), alt.Tooltip("domain_list:N", title="Domains")]
            )
            .properties(width=600, height=400, title="DMARC Policy Distribution")
        )
        st.altair_chart(chart_policy, use_container_width=True)
    if show_chart_fo:
        fo_data = df.groupby("dmarc_fo")["domain"].agg(["count", lambda x: "\n".join(x)]).reset_index()
        fo_data.columns = ["dmarc_fo", "domain_count", "domain_list"]
        chart_fo = (
            alt.Chart(fo_data)
            .mark_bar()
            .encode(
                x=alt.X("dmarc_fo:N", sort="-y", title="DMARC FO"),
                y=alt.Y("domain_count:Q", title="Domains"),
                color=alt.Color("dmarc_fo:N"),
                tooltip=[alt.Tooltip("domain_count:Q", title="Count"), alt.Tooltip("domain_list:N", title="Domains")]
            )
            .properties(width=600, height=400, title="DMARC FO Distribution")
        )
        st.altair_chart(chart_fo, use_container_width=True)
    if show_chart_rua:
        rua_data = df.groupby("dmarc_rua")["domain"].agg(["count", lambda x: "\n".join(x)]).reset_index()
        rua_data.columns = ["dmarc_rua", "domain_count", "domain_list"]
        chart_rua = (
            alt.Chart(rua_data)
            .mark_bar()
            .encode(
                x=alt.X("dmarc_rua:N", sort="-y", title="DMARC RUA"),
                y=alt.Y("domain_count:Q", title="Domains"),
                color=alt.Color("dmarc_rua:N"),
                tooltip=[alt.Tooltip("domain_count:Q", title="Count"), alt.Tooltip("domain_list:N", title="Domains")]
            )
            .properties(width=600, height=400, title="DMARC RUA Distribution")
        )
        st.altair_chart(chart_rua, use_container_width=True)
    if show_chart_combos:
        combos = []
        for idx, row in df.iterrows():
            spf_m = not row["spf"]
            dmarc_m = not row["dmarc"]
            dkim_m = not row["dkim"]
            if not spf_m and not dkim_m and not dmarc_m:
                combos.append("All Present")
            elif spf_m and dkim_m and dmarc_m:
                combos.append("All Missing")
            elif spf_m and dkim_m and not dmarc_m:
                combos.append("Missing SPF+DMARC")
            elif spf_m and not dkim_m and dmarc_m:
                combos.append("Missing SPF+DKIM")
            elif not spf_m and dkim_m and dmarc_m:
                combos.append("Missing DMARC+DKIM")
            elif spf_m and not dkim_m and not dmarc_m:
                combos.append("Only SPF Missing")
            elif not spf_m and dkim_m and not dmarc_m:
                combos.append("Only DMARC Missing")
            elif not spf_m and not dkim_m and dmarc_m:
                combos.append("Only DKIM Missing")
            else:
                combos.append("Undefined")
        df["combo"] = combos
        combo_data = df.groupby("combo")["domain"].agg(["count", lambda x: "\n".join(x)]).reset_index()
        combo_data.columns = ["combo", "domain_count", "domain_list"]
        chart_stacked = (
            alt.Chart(combo_data)
            .mark_bar()
            .encode(
                x=alt.X("combo:N", sort="-y", title="Combo Category"),
                y=alt.Y("domain_count:Q", title="Domains"),
                color="combo:N",
                tooltip=[alt.Tooltip("domain_count:Q", title="Count"), alt.Tooltip("domain_list:N", title="Domains")]
            )
            .properties(width=600, height=400, title="Stacked Bar (Combos)")
        )
        st.altair_chart(chart_stacked, use_container_width=True)
        donut_chart = (
            alt.Chart(combo_data)
            .mark_arc(innerRadius=70)
            .encode(
                theta=alt.Theta("domain_count:Q", stack=True),
                color=alt.Color("combo:N", legend=None),
                tooltip=[alt.Tooltip("combo:N", title="Combo"), alt.Tooltip("domain_count:Q", title="Count"), alt.Tooltip("domain_list:N", title="Domains")]
            )
            .properties(width=400, height=400, title="Donut Chart")
        )
        st.altair_chart(donut_chart, use_container_width=False)
    if show_chart_history:
        st.write("**Historical Timeline** from historical_data.csv (if any).")
        if os.path.exists("historical_data.csv"):
            df_history = pd.read_csv("historical_data.csv")
        else:
            df_history = pd.DataFrame(columns=["date","total_domains","fully_protected","missing_spf","missing_dkim","missing_dmarc"])
        if not df_history.empty:
            chart_history = (
                alt.Chart(df_history)
                .mark_line(point=True)
                .encode(
                    x=alt.X("date:T", title="Date"),
                    y=alt.Y("fully_protected:Q", title="# Fully Protected"),
                    tooltip=[alt.Tooltip("date:T", title="Date"), alt.Tooltip("fully_protected:Q", title="# Fully Protected"), alt.Tooltip("total_domains:Q", title="Total")]
                )
                .properties(width=700, height=350, title="Historical Trend of Fully Protected Domains Over Time")
            )
            st.altair_chart(chart_history, use_container_width=True)
        else:
            st.info("No historical data yet.")

if __name__ == "__main__":
    main()
