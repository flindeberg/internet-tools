import scrapy
from scrapy import linkextractors

from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor

import os
from urllib.parse import urlparse

class IcannSpider(CrawlSpider):

    # .remove
    name = 'icann'
    allowed_domains = ["icann.org"]
    start_urls = ['https://www.icann.org/resources/pages/cctlds/cctlds-en', 'https://icann.org']
    rules = [Rule(LinkExtractor(deny_extensions=[ele for ele in linkextractors.IGNORED_EXTENSIONS if ele != "pdf"]), callback='parse_item', follow=True)]

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
