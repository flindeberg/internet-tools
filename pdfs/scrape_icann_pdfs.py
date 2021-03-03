import scrapy
from scrapy import linkextractors
from scrapy.http.request import Request

from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor
from scrapy.dupefilters import RFPDupeFilter

import os
from urllib.parse import urlparse

class MyDupeFilter(RFPDupeFilter):
    ## class for catching pdf dupes due to auto-generated links

    def request_fingerprint(self, req : Request) -> str:
        if req.url.endswith("application/pdf"):
            # get the part of the url which seems to identify the file itself
            pdfname = str.join('-', req.url.split('/')[-2].split('-')[0:-3]) + ".pdf"
            print("Caught pdf-export called {:}".format(pdfname))
            return "icann.org/mypdfs/{:}".format(pdfname)
        else:
            return super().request_fingerprint(req)

class IcannSpider(CrawlSpider):

    custom_settings = {
        'DUPEFILTER_CLASS': 'scrape_icann_pdfs.MyDupeFilter',
    }

    # .remove
    name = 'icann'
    allowed_domains = ["icann.org"]
    start_urls = ['https://www.icann.org/resources/pages/cctlds/cctlds-en', 'https://icann.org']
    rules = [Rule(LinkExtractor(
                    deny_extensions=(ele for ele in linkextractors.IGNORED_EXTENSIONS if ele != "pdf"),
                    ), 
                callback='parse_item', follow=True)]

    ## Parse already downloaded urls
    def parse_item(self, response):
        ## Check if we have something which says its a pdf, and save the bytes
        if response.url.endswith("pdf"):
            print("Found PDF at:" + response.url)

            url = urlparse(response.url)
            filename = "pdfs/" + os.path.basename(url.path)

            with open(filename, "wb") as f:
                f.write(response.body)

            pre, ext = os.path.splitext(filename)

            with open(pre + ".txt", "w") as f:
                f.write(str(response.url) + "\n")