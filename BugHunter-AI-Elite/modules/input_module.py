import re
import json
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from modules.logging_config import logger


def parse_url(url):
    try:
        parsed = urlparse(url)
        return {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "path": parsed.path,
            "params": parsed.params,
            "query": parsed.query,
            "fragment": parsed.fragment
        }
    except Exception as e:
        logger.error(f"URL parse error: {e}")
        return None


def normalize_url(url):
    parsed = parse_url(url)
    if not parsed:
        return None
    
    if not parsed["scheme"]:
        parsed["scheme"] = "https"
    
    netloc = parsed["netloc"].lower().replace("www.", "")
    path = parsed["path"] or "/"
    
    normalized = f"{parsed['scheme']}://{netloc}{path}"
    if parsed["query"]:
        normalized += f"?{parsed['query']}"
    
    return normalized


def validate_target(url, scope_domains=None):
    parsed = parse_url(url)
    if not parsed or not parsed["netloc"]:
        return False, "Invalid URL format"
    
    if parsed["scheme"] not in ["http", "https"]:
        return False, "Only HTTP/HTTPS supported"
    
    if scope_domains:
        if parsed["netloc"] not in scope_domains:
            return False, "Target not in scope"
    
    return True, "Valid target"


def extract_domain(url):
    parsed = parse_url(url)
    return parsed["netloc"] if parsed else None


def build_url(base, path=None, params=None):
    if path:
        url = urljoin(base, path)
    else:
        url = base
    
    if params:
        parsed = parse_url(url)
        query = parse_qs(parsed["query"]) if parsed["query"] else {}
        query.update(params)
        url = urlunparse((
            parsed["scheme"], parsed["netloc"], parsed["path"],
            parsed["params"], urlencode(query, doseq=True), ""
        ))
    
    return url


def is_same_domain(url1, url2):
    return extract_domain(url1) == extract_domain(url2)


def get_params_from_url(url):
    parsed = parse_url(url)
    if parsed and parsed["query"]:
        return list(parse_qs(parsed["query"]).keys())
    return []


def inject_param(url, param_name, param_value):
    params = parse_qs(urlparse(url).query) if urlparse(url).query else {}
    params[param_name] = [param_value]
    new_query = urlencode(params, doseq=True)
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ""))