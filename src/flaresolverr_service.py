import logging
import os
import platform
import random
import sys
import tempfile
import time
from datetime import timedelta
from html import escape
from urllib.parse import unquote, quote

from func_timeout import FunctionTimedOut, func_timeout
from selenium.common import TimeoutException
from selenium.webdriver.chrome.webdriver import WebDriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.expected_conditions import staleness_of
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.wait import WebDriverWait

import utils
from dtos import (STATUS_ERROR, STATUS_OK, ChallengeResolutionResultT,
                  ChallengeResolutionT, HealthResponse, IndexResponse,
                  V1RequestBase, V1ResponseBase)
from sessions import SessionsStorage

ACCESS_DENIED_TITLES = [
    # Cloudflare
    'Access denied',
    # Cloudflare http://bitturk.net/ Firefox
    'Attention Required! | Cloudflare'
]
ACCESS_DENIED_SELECTORS = [
    # Cloudflare
    'div.cf-error-title span.cf-code-label span',
    # Cloudflare http://bitturk.net/ Firefox
    '#cf-error-details div.cf-error-overview h1'
]
CHALLENGE_TITLES = [
    # Cloudflare
    'Just a moment...',
    # DDoS-GUARD
    'DDoS-Guard'
]
CHALLENGE_SELECTORS = [
    # Cloudflare
    '#cf-challenge-running', '.ray_id', '.attack-box', '#cf-please-wait', '#challenge-spinner', '#trk_jschal_js', '#turnstile-wrapper', '.lds-ring',
    # Custom CloudFlare for EbookParadijs, Film-Paleis, MuziekFabriek and Puur-Hollands
    'td.info #js_info',
    # Fairlane / pararius.com
    'div.vc div.text-box h2'
]

TURNSTILE_SELECTORS = [
    "input[name='cf-turnstile-response']"
]
# containers of the Turnstile widget, used to click the verify checkbox by coordinates
TURNSTILE_WIDGET_SELECTORS = [
    '#turnstile-wrapper', 'div.cf-turnstile', 'div[id^="cf-chl-widget-"]'
]
# distance in pixels from the left edge of the widget to the center of the checkbox
TURNSTILE_CHECKBOX_OFFSET_X = 30
# seconds to wait after a click before trying again, clicking too often resets the widget
CHALLENGE_CLICK_INTERVAL = 5
# seconds reserved before maxTimeout to exit the challenge loop cleanly
DEADLINE_MARGIN = 3

SESSIONS_STORAGE = SessionsStorage()


def test_browser_installation():
    logging.info("Testing web browser installation...")
    logging.info("Platform: " + platform.platform())

    chrome_exe_path = utils.get_chrome_exe_path()
    if chrome_exe_path is None:
        logging.error("Chrome / Chromium web browser not installed!")
        sys.exit(1)
    else:
        logging.info("Chrome / Chromium path: " + chrome_exe_path)

    chrome_major_version = utils.get_chrome_major_version()
    if chrome_major_version == '':
        logging.error("Chrome / Chromium version not detected!")
        sys.exit(1)
    else:
        logging.info("Chrome / Chromium major version: " + chrome_major_version)

    logging.info("Launching web browser...")
    user_agent = utils.get_user_agent()
    logging.info("FlareSolverr User-Agent: " + user_agent)
    logging.info("Test successful!")


def index_endpoint() -> IndexResponse:
    res = IndexResponse({})
    res.msg = "FlareSolverr is ready!"
    res.version = utils.get_flaresolverr_version()
    res.userAgent = utils.get_user_agent()
    return res


def health_endpoint() -> HealthResponse:
    res = HealthResponse({})
    res.status = STATUS_OK
    return res


def controller_v1_endpoint(req: V1RequestBase) -> V1ResponseBase:
    start_ts = int(time.time() * 1000)
    logging.info(f"Incoming request => POST /v1 body: {utils.object_to_dict(req)}")
    res: V1ResponseBase
    try:
        res = _controller_v1_handler(req)
    except Exception as e:
        res = V1ResponseBase({})
        res.__error_500__ = True
        res.status = STATUS_ERROR
        res.message = "Error: " + str(e)
        logging.error(res.message)

    res.startTimestamp = start_ts
    res.endTimestamp = int(time.time() * 1000)
    res.version = utils.get_flaresolverr_version()
    logging.debug(f"Response => POST /v1 body: {utils.object_to_dict(res)}")
    logging.info(f"Response in {(res.endTimestamp - res.startTimestamp) / 1000} s")
    return res


def _controller_v1_handler(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.cmd is None:
        raise Exception("Request parameter 'cmd' is mandatory.")
    if req.headers is not None:
        logging.warning("Request parameter 'headers' was removed in FlareSolverr v2.")
    if req.userAgent is not None:
        logging.warning("Request parameter 'userAgent' was removed in FlareSolverr v2.")

    # set default values
    if req.maxTimeout is None or int(req.maxTimeout) < 1:
        req.maxTimeout = 60000

    # execute the command
    res: V1ResponseBase
    if req.cmd == 'sessions.create':
        res = _cmd_sessions_create(req)
    elif req.cmd == 'sessions.list':
        res = _cmd_sessions_list(req)
    elif req.cmd == 'sessions.destroy':
        res = _cmd_sessions_destroy(req)
    elif req.cmd == 'request.get':
        res = _cmd_request_get(req)
    elif req.cmd == 'request.post':
        res = _cmd_request_post(req)
    else:
        raise Exception(f"Request parameter 'cmd' = '{req.cmd}' is invalid.")

    return res


def _cmd_request_get(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.url is None:
        raise Exception("Request parameter 'url' is mandatory in 'request.get' command.")
    if req.postData is not None:
        raise Exception("Cannot use 'postBody' when sending a GET request.")
    if req.returnRawHtml is not None:
        logging.warning("Request parameter 'returnRawHtml' was removed in FlareSolverr v2.")
    if req.download is not None:
        logging.warning("Request parameter 'download' was removed in FlareSolverr v2.")

    challenge_res = _resolve_challenge(req, 'GET')
    res = V1ResponseBase({})
    res.status = challenge_res.status
    res.message = challenge_res.message
    res.solution = challenge_res.result
    return res


def _cmd_request_post(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.postData is None:
        raise Exception("Request parameter 'postData' is mandatory in 'request.post' command.")
    if req.returnRawHtml is not None:
        logging.warning("Request parameter 'returnRawHtml' was removed in FlareSolverr v2.")
    if req.download is not None:
        logging.warning("Request parameter 'download' was removed in FlareSolverr v2.")

    challenge_res = _resolve_challenge(req, 'POST')
    res = V1ResponseBase({})
    res.status = challenge_res.status
    res.message = challenge_res.message
    res.solution = challenge_res.result
    return res


def _cmd_sessions_create(req: V1RequestBase) -> V1ResponseBase:
    logging.debug("Creating new session...")

    session, fresh = SESSIONS_STORAGE.create(session_id=req.session, proxy=req.proxy)
    session_id = session.session_id

    if not fresh:
        return V1ResponseBase({
            "status": STATUS_OK,
            "message": "Session already exists.",
            "session": session_id
        })

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "Session created successfully.",
        "session": session_id
    })


def _cmd_sessions_list(req: V1RequestBase) -> V1ResponseBase:
    session_ids = SESSIONS_STORAGE.session_ids()

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "",
        "sessions": session_ids
    })


def _cmd_sessions_destroy(req: V1RequestBase) -> V1ResponseBase:
    session_id = req.session
    existed = SESSIONS_STORAGE.destroy(session_id)

    if not existed:
        raise Exception("The session doesn't exist.")

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "The session has been removed."
    })


def _resolve_challenge(req: V1RequestBase, method: str) -> ChallengeResolutionT:
    timeout = int(req.maxTimeout) / 1000
    driver = None
    try:
        if req.session:
            session_id = req.session
            ttl = timedelta(minutes=req.session_ttl_minutes) if req.session_ttl_minutes else None
            session, fresh = SESSIONS_STORAGE.get(session_id, ttl)

            if fresh:
                logging.debug(f"new session created to perform the request (session_id={session_id})")
            else:
                logging.debug(f"existing session is used to perform the request (session_id={session_id}, "
                              f"lifetime={str(session.lifetime())}, ttl={str(ttl)})")

            driver = session.driver
        else:
            driver = utils.get_webdriver(req.proxy)
            logging.debug('New instance of webdriver has been created to perform the request')
        return func_timeout(timeout, _evil_logic, (req, driver, method))
    except FunctionTimedOut:
        raise Exception(f'Error solving the challenge. Timeout after {timeout} seconds.')
    except Exception as e:
        raise Exception('Error solving the challenge. ' + str(e).replace('\n', '\\n'))
    finally:
        if not req.session and driver is not None:
            if utils.PLATFORM_VERSION == "nt":
                driver.close()
            driver.quit()
            logging.debug('A used instance of webdriver has been destroyed')


def _reset_focus(driver: WebDriver):
    # put the focus at the top of the page so the TAB count is deterministic
    driver.execute_script("""
        let old = document.getElementById('__focus_helper');
        if (old) old.remove();

        let el = document.createElement('button');
        el.id = '__focus_helper';
        el.style.position = 'fixed';
        el.style.top = '0';
        el.style.left = '0';
        el.style.opacity = '0.01';
        el.style.pointerEvents = 'none';
        document.body.prepend(el);
        el.focus();
    """)


def _get_turnstile_value(driver: WebDriver) -> str:
    try:
        for token_input in driver.find_elements(By.CSS_SELECTOR, TURNSTILE_SELECTORS[0]):
            value = token_input.get_attribute("value")
            if value:
                return value
    except Exception:
        # the page can reload while we read it
        pass
    return ""


def _find_turnstile_widget(driver: WebDriver):
    # the checkbox lives in a cross-origin iframe inside a closed shadow root,
    # so we locate the visible container around it and click by coordinates
    candidates = []
    try:
        for selector in TURNSTILE_WIDGET_SELECTORS:
            candidates.extend(driver.find_elements(By.CSS_SELECTOR, selector))
        for token_input in driver.find_elements(By.CSS_SELECTOR, TURNSTILE_SELECTORS[0]):
            candidates.append(token_input.find_element(By.XPATH, ".."))
    except Exception:
        # the page can reload while we read it
        pass

    fallback = None
    for element in candidates:
        try:
            rect = driver.execute_script("""
                arguments[0].scrollIntoView({block: 'center'});
                const r = arguments[0].getBoundingClientRect();
                return {x: r.x, y: r.y, width: r.width, height: r.height};
            """, element)
        except Exception:
            continue
        if rect['width'] < 50 or rect['height'] < 30:
            continue
        # the Turnstile widget is ~300x65, prefer an element with that size
        if rect['width'] <= 450 and rect['height'] <= 100:
            return rect
        if fallback is None:
            fallback = rect
    return fallback


def _mouse_click(driver: WebDriver, x: float, y: float):
    # CDP input events are dispatched as trusted events, like a real user
    start_x, start_y = x - random.uniform(80, 160), y + random.uniform(20, 60)
    steps = 5
    for i in range(1, steps + 1):
        driver.execute_cdp_cmd("Input.dispatchMouseEvent", {
            "type": "mouseMoved",
            "x": start_x + (x - start_x) * i / steps,
            "y": start_y + (y - start_y) * i / steps,
        })
        time.sleep(random.uniform(0.02, 0.08))
    for event_type in ("mousePressed", "mouseReleased"):
        driver.execute_cdp_cmd("Input.dispatchMouseEvent", {
            "type": event_type, "x": x, "y": y, "button": "left", "clickCount": 1,
        })
        time.sleep(random.uniform(0.05, 0.15))


def _click_verify_button(driver: WebDriver) -> bool:
    buttons = driver.find_elements(By.XPATH, "//input[@type='button' and @value='Verify you are human']")
    if len(buttons) == 0:
        return False
    ActionChains(driver).move_to_element(buttons[0]).click(buttons[0]).perform()
    return True


def _press_tabs_and_space(driver: WebDriver, num_tabs: int):
    actions = ActionChains(driver)
    for _ in range(num_tabs):
        actions.send_keys(Keys.TAB).pause(0.1)
    actions.pause(1)
    actions.send_keys(Keys.SPACE).perform()


def _click_challenge(driver: WebDriver, click_attempt: int) -> str:
    """Try to pass the challenge interaction. Returns a description of what was done."""
    driver.switch_to.default_content()

    try:
        if _click_verify_button(driver):
            return "clicked 'Verify you are human' button"
    except Exception:
        pass

    rect = _find_turnstile_widget(driver)
    if rect is not None:
        x = rect['x'] + TURNSTILE_CHECKBOX_OFFSET_X + random.uniform(-3, 3)
        y = rect['y'] + rect['height'] / 2 + random.uniform(-3, 3)
        try:
            _mouse_click(driver, x, y)
            return f"mouse click at ({x:.0f}, {y:.0f}) on widget {rect['width']:.0f}x{rect['height']:.0f}"
        except Exception as e:
            logging.debug(f"Mouse click with CDP failed: {e}")

    # fallback: the widget container was not found, try the keyboard with a different number of TABs each time
    num_tabs = (click_attempt - 1) % 3 + 1
    try:
        _reset_focus(driver)
        _press_tabs_and_space(driver, num_tabs)
        return f"widget not found, pressed TAB x{num_tabs} + SPACE"
    except Exception as e:
        return f"widget not found, keyboard fallback failed: {e}"


def click_verify(driver: WebDriver, num_tabs: int = 1):
    try:
        logging.debug("Try to find the Cloudflare verify checkbox...")
        time.sleep(5)
        _press_tabs_and_space(driver, num_tabs)
        logging.debug(f"Pressed TAB x{num_tabs} + SPACE to reach the Cloudflare verify checkbox")
    except Exception:
        logging.debug("Cloudflare verify checkbox not found on the page.")
    finally:
        driver.switch_to.default_content()

    try:
        if _click_verify_button(driver):
            logging.debug("The Cloudflare 'Verify you are human' button found and clicked!")
        else:
            logging.debug("The Cloudflare 'Verify you are human' button not found on the page.")
    except Exception:
        logging.debug("The Cloudflare 'Verify you are human' button not found on the page.")

    time.sleep(2)


def _get_turnstile_token(driver: WebDriver, tabs: int, deadline: float):
    token_input = driver.find_element(By.CSS_SELECTOR, "input[name='cf-turnstile-response']")
    current_value = token_input.get_attribute("value")
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        click_verify(driver, num_tabs=tabs)
        turnstile_token = token_input.get_attribute("value")
        if turnstile_token:
            if turnstile_token != current_value:
                logging.info(f"Turnstile token: {turnstile_token}")
                return turnstile_token
        logging.debug(f"Turnstile token not received after attempt {attempt} (TAB x{tabs} + SPACE), "
                      f"check that tabs_till_verify is right for this site")

        _reset_focus(driver)
        time.sleep(1)
    _save_debug_snapshot(driver)
    raise Exception(f'Turnstile token not received after {attempt} attempts with tabs_till_verify={tabs}.')


def _resolve_turnstile_captcha(req: V1RequestBase, driver: WebDriver, deadline: float):
    turnstile_token = None
    if req.tabs_till_verify is not None:
        logging.debug(f'Navigating to... {req.url} in order to pass the turnstile challenge')
        driver.get(req.url)

        turnstile_challenge_found = False
        for selector in TURNSTILE_SELECTORS:
            found_elements = driver.find_elements(By.CSS_SELECTOR, selector)   
            if len(found_elements) > 0:
                turnstile_challenge_found = True
                logging.info("Turnstile challenge detected. Selector found: " + selector)
                break
        if turnstile_challenge_found:
            turnstile_token = _get_turnstile_token(driver=driver, tabs=req.tabs_till_verify, deadline=deadline)
        else:
            logging.debug(f'Turnstile challenge not found')
    return turnstile_token


def _is_challenge_present(driver: WebDriver) -> bool:
    page_title = driver.title.lower()
    if any(title.lower() == page_title for title in CHALLENGE_TITLES):
        return True
    for selector in CHALLENGE_SELECTORS:
        if len(driver.find_elements(By.CSS_SELECTOR, selector)) > 0:
            return True
    return False


def _wait_challenge_gone(driver: WebDriver, timeout: float) -> bool:
    try:
        WebDriverWait(driver, max(timeout, 0.5)).until_not(_is_challenge_present)
        return True
    except TimeoutException:
        return False


def _save_debug_snapshot(driver: WebDriver):
    # only in debug mode, save what the browser was showing to find out why the challenge failed
    if not logging.getLogger().isEnabledFor(logging.DEBUG):
        return
    try:
        base_path = os.path.join(tempfile.gettempdir(), f"flaresolverr_{int(time.time())}")
        driver.save_screenshot(base_path + ".png")
        with open(base_path + ".html", "w", encoding="utf-8") as f:
            f.write(driver.page_source)
        logging.debug(f"Saved the page screenshot and HTML in {base_path}.png / {base_path}.html")
    except Exception as e:
        logging.debug(f"Unable to save the page screenshot and HTML: {e}")


def _evil_logic(req: V1RequestBase, driver: WebDriver, method: str) -> ChallengeResolutionT:
    res = ChallengeResolutionT({})
    res.status = STATUS_OK
    res.message = ""
    deadline = time.monotonic() + int(req.maxTimeout) / 1000 - DEADLINE_MARGIN

    # optionally block resources like images/css/fonts using CDP
    disable_media = utils.get_config_disable_media()
    if req.disableMedia is not None:
        disable_media = req.disableMedia
    if disable_media:
        block_urls = [
            # Images
            "*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.bmp", "*.svg", "*.ico",
            "*.PNG", "*.JPG", "*.JPEG", "*.GIF", "*.WEBP", "*.BMP", "*.SVG", "*.ICO",
            "*.tiff", "*.tif", "*.jpe", "*.apng", "*.avif", "*.heic", "*.heif",
            "*.TIFF", "*.TIF", "*.JPE", "*.APNG", "*.AVIF", "*.HEIC", "*.HEIF",
            # Stylesheets
            "*.css",
            "*.CSS",
            # Fonts
            "*.woff", "*.woff2", "*.ttf", "*.otf", "*.eot",
            "*.WOFF", "*.WOFF2", "*.TTF", "*.OTF", "*.EOT"
        ]
        try:
            logging.debug("Network.setBlockedURLs: %s", block_urls)
            driver.execute_cdp_cmd("Network.enable", {})
            driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": block_urls})
        except Exception:
            # if CDP commands are not available or fail, ignore and continue
            logging.debug("Network.setBlockedURLs failed or unsupported on this webdriver")

    # navigate to the page
    logging.debug(f"Navigating to... {req.url}")
    turnstile_token = None

    if method == "POST":
        _post_request(req, driver)
    else:
        if req.tabs_till_verify is None:
            driver.get(req.url)
        else:
            turnstile_token = _resolve_turnstile_captcha(req, driver, deadline)

    # set cookies if required
    if req.cookies is not None and len(req.cookies) > 0:
        logging.debug(f'Setting cookies...')
        for cookie in req.cookies:
            driver.delete_cookie(cookie['name'])
            driver.add_cookie(cookie)
        # reload the page
        if method == 'POST':
            _post_request(req, driver)
        else:
            driver.get(req.url)

    # wait for the page
    if utils.get_config_log_html():
        logging.debug(f"Response HTML:\n{driver.page_source}")
    html_element = driver.find_element(By.TAG_NAME, "html")
    page_title = driver.title

    # find access denied titles
    for title in ACCESS_DENIED_TITLES:
        if page_title.startswith(title):
            raise Exception('Cloudflare has blocked this request. '
                            'Probably your IP is banned for this site, check in your web browser.')
    # find access denied selectors
    for selector in ACCESS_DENIED_SELECTORS:
        found_elements = driver.find_elements(By.CSS_SELECTOR, selector)
        if len(found_elements) > 0:
            raise Exception('Cloudflare has blocked this request. '
                            'Probably your IP is banned for this site, check in your web browser.')

    # find challenge by title
    challenge_found = False
    for title in CHALLENGE_TITLES:
        if title.lower() == page_title.lower():
            challenge_found = True
            logging.info("Challenge detected. Title found: " + page_title)
            break
    if not challenge_found:
        # find challenge by selectors
        for selector in CHALLENGE_SELECTORS:
            found_elements = driver.find_elements(By.CSS_SELECTOR, selector)
            if len(found_elements) > 0:
                challenge_found = True
                logging.info("Challenge detected. Selector found: " + selector)
                break

    browser_wait_timeout = utils.get_config_browser_wait_timeout()
    if challenge_found:
        # first let the challenge pass on its own, clicking too early can reset it
        grace_seconds = utils.get_config_challenge_grace_seconds()
        logging.debug(f"Waiting up to {grace_seconds} s for the challenge to pass on its own...")
        click_attempt = 0
        solved = _wait_challenge_gone(driver, min(grace_seconds, deadline - time.monotonic()))
        while not solved:
            if time.monotonic() >= deadline:
                _save_debug_snapshot(driver)
                raise Exception(f'Challenge still present after {click_attempt} click attempts '
                                f'(page title: "{driver.title}").')

            click_attempt += 1
            token_before = _get_turnstile_value(driver)
            action = _click_challenge(driver, click_attempt)
            logging.debug(f"Click attempt {click_attempt}: {action}")

            # update the html (cloudflare reloads the page every 5 s)
            html_element = driver.find_element(By.TAG_NAME, "html")

            wait = min(max(browser_wait_timeout, CHALLENGE_CLICK_INTERVAL), deadline - time.monotonic())
            solved = _wait_challenge_gone(driver, wait)
            if not solved:
                token_changed = _get_turnstile_value(driver) != token_before
                logging.debug(f"Challenge still present after click attempt {click_attempt} "
                              f"(title: \"{driver.title}\", turnstile token changed: {token_changed})")

        # waits until cloudflare redirection ends
        logging.debug("Waiting for redirect")
        # noinspection PyBroadException
        try:
            WebDriverWait(driver, browser_wait_timeout).until(staleness_of(html_element))
        except Exception:
            logging.debug("Timeout waiting for redirect")

        logging.info("Challenge solved!")
        res.message = "Challenge solved!"
    else:
        logging.info("Challenge not detected!")
        res.message = "Challenge not detected!"

    challenge_res = ChallengeResolutionResultT({})
    challenge_res.url = driver.current_url
    challenge_res.status = 200  # todo: fix, selenium not provides this info
    challenge_res.userAgent = utils.get_user_agent(driver)
    challenge_res.turnstile_token = turnstile_token

    if not req.returnOnlyCookies:
        challenge_res.headers = {}  # todo: fix, selenium not provides this info

        if req.waitInSeconds and req.waitInSeconds > 0:
            logging.info("Waiting " + str(req.waitInSeconds) + " seconds before returning the response...")
            time.sleep(req.waitInSeconds)

        challenge_res.response = driver.page_source

    if req.returnScreenshot:
        challenge_res.screenshot = driver.get_screenshot_as_base64()

    # Get cookies after all waits to capture cookies set during JavaScript execution
    challenge_res.cookies = driver.get_cookies()

    res.result = challenge_res
    return res


def _post_request(req: V1RequestBase, driver: WebDriver):
    post_form = f'<form id="hackForm" action="{req.url}" method="POST">'
    query_string = req.postData if req.postData and req.postData[0] != '?' else req.postData[1:] if req.postData else ''
    pairs = query_string.split('&')
    for pair in pairs:
        parts = pair.split('=', 1)
        # noinspection PyBroadException
        try:
            name = unquote(parts[0])
        except Exception:
            name = parts[0]
        if name == 'submit':
            continue
        # noinspection PyBroadException
        try:
            value = unquote(parts[1]) if len(parts) > 1 else ''
        except Exception:
            value = parts[1] if len(parts) > 1 else ''
        # Protection of " character, for syntax
        value=value.replace('"','&quot;')
        post_form += f'<input type="text" name="{escape(quote(name))}" value="{escape(quote(value))}"><br>'
    post_form += '</form>'
    html_content = f"""
        <!DOCTYPE html>
        <html>
        <body>
            {post_form}
            <script>document.getElementById('hackForm').submit();</script>
        </body>
        </html>"""
    driver.get("data:text/html;charset=utf-8,{html_content}".format(html_content=html_content))
