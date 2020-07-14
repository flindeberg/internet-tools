import asyncio

from pyppeteer import launch

import pprint


async def main():
    browser = await launch(headless=True)
    page1 = await browser.newPage()
    
    context = await browser.createIncognitoBrowserContext()
    
    # Create a new page in a pristine context.
    page = await context.newPage()
    # Do stuff
    await getpage(page, 'https://www.svd.se', "svd_incog")
    #await getpage(page1, 'https://www.svd.se', "svd")
    #await getpage(page1, 'https://www.dn.se', "dn")
    #await getpage(page, 'https://www.folkhalsomyndigheten.se', "fhm")
    
    # close last
    await browser.close()

def printstuff(data = None, moredata = None):
  print("in printstuff")
  pprint.pprint(data)
  pprint.pprint(moredata)

def newlistener(data = None, moredata = None):
  print("in newlistener")
  pprint.pprint(data)
  pprint.pprint(moredata)

def donesoemthing(data = None, moredata = None):
  print("Remote has done something")
  pprint.pprint(data)
  pprint.pprint(moredata)

def respgotten(data = None, moredata = None):
  print("Response gotten")
  pprint.pprint(data)
  pprint.pprint(moredata)

async def getpage(page, url: str, text: str):
    # Do stuff
    await page.setViewport({'width': 1920, 'height': 1020})
    await page.emulateMedia('screen')

    target = page.target
    session = await target.createCDPSession()

    session.on("new_listener", newlistener)

    #ans = await session.send("harEntry")    
    @session.on("harEntry")
    def event_handler(data = None, v = None):
      print("bang bang")
      print(data)

    @session.once("connected")
    def evh(k = None, v = None):
      print("connected fired")
    
    session.once("connected", printstuff)

    session.on("harEntry", printstuff)
    
    session.emit("connected", "pizza", "lök") #, "some data", "some more")
    session.emit("harEntry", "pizza", "lök") #, "some data", "some more")

    session.on("Network.responseReceived", respgotten)

    #sent = await session.send("Page.navigate", {"url" : "https://github.com"})

    pprint.pprint(session._events)

    await page.tracing.start({'path': 'trace_{:}.json'.format(text)})

    await page.goto(url, waitUntill="networkidle2")
    await page.screenshot({'path': 'example_{:}.png'.format(text), 'fullPage': True})

    cookies = await page.cookies()
    pprint.pprint("{:} cookies: {:}".format(text, len(cookies)))

    await page.pdf({'path': 'example_{:}.pdf'.format(text), 'width': '1920px', 'height': '5120px'})

    events = await page.tracing.stop()

    pprint.pprint(events)

asyncio.get_event_loop().run_until_complete(main())
