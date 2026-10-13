# Copyright (c) 2026 Fredrik Lindeberg <flindeberg@gmail.com>
# All rights reserved.

"""
Captures HAR files of websites with headless Chromium, through Playwright.

This is the default way generatemap.py captures HARs. The legacy way,
generatehar.sh with chrome-har-capturer, uses the same settings: all urls
in one HAR, 30 s for each page to load, 4 s more for late requests, one
retry, no cache. Compared to it, Playwright's HARs have cookies and
request/response sizes, which chrome-har-capturer no longer records with
current Chrome, and a few more requests and hosts (e.g. fonts).

Needs the browser once: python -m playwright install chromium
"""

## Give each page 30 s to load, and wait 4 s after load, retry once
PAGE_TIMEOUT_MS = 30000
GRACE_MS = 4000
RETRIES = 1


def capture(urls, harfile: str, quiet: bool = False) -> None:
    """
    Visits urls in order, in one fresh browser context, and saves all
    requests to harfile. A page that does not load (in time) is retried
    once; what it did load is kept in the HAR either way.
    """
    # imported here, so the rest works without playwright (e.g. with -e)
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            context = browser.new_context(
                record_har_path=harfile,
                # only the requests, not the content (as chrome-har-capturer)
                record_har_content="omit",
                # their requests would not be recorded
                service_workers="block",
            )
            for url in urls:
                page = context.new_page()
                _disable_cache(context, page)
                for attempt in range(1 + RETRIES):
                    try:
                        page.goto(url, wait_until="load", timeout=PAGE_TIMEOUT_MS)
                        break
                    except PlaywrightError as e:
                        if not quiet:
                            print(
                                "Could not load {:} (attempt {:}): {:}".format(
                                    url, attempt + 1, str(e).splitlines()[0]
                                )
                            )
                page.wait_for_timeout(GRACE_MS)
                page.close()
            # the HAR is written when the context closes
            context.close()
        finally:
            browser.close()


def _disable_cache(context, page) -> None:
    """
    Turns off the browser cache for page, so that visiting the same site
    again (generatemap.py -n) makes the same requests, and the HAR has
    their real transfer sizes (chrome-har-capturer: --disk-cache-size=0)
    """
    cdp = context.new_cdp_session(page)
    cdp.send("Network.enable")
    cdp.send("Network.setCacheDisabled", {"cacheDisabled": True})
