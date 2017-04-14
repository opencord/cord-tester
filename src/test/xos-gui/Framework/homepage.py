import unittest
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import sys
import time
import os
sys.path.append(os.path.join(sys.path[0], 'utils'))
from UI_Utils import *


class homepage():
    """Test cases for XOS"""

    @staticmethod
    def testHomePageElements(file, url, username):
        driver = UI_Utils.setUp()
        wait = WebDriverWait(driver, 10)

        password = UI_Utils.getPasswd(file)
        UI_Utils.doLogin(driver, username, password)

        wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, 'xos-nav')))

        # check main elements
        nav = driver.find_element_by_css_selector('xos-nav')
        header = driver.find_element_by_css_selector('xos-header')
        searchbar = driver.find_element_by_css_selector('xos-header .navbar-form > input')

        assert nav, "nav component is missing"
        assert header, "header component is missing"
        assert searchbar, "searchbar component is missing"

        # check navigation
        nav_items = driver.find_elements_by_css_selector('xos-nav .nav.luna-nav > li')
        assert len(nav_items) > 0

        core_items = nav_items[1].find_elements_by_css_selector('li')
        assert len(core_items) > 0

        UI_Utils.tearDown(driver)

    @staticmethod
    def testSearchBox(file, url, username):
        driver = UI_Utils.setUp()
        wait = WebDriverWait(driver, 10)

        password = UI_Utils.getPasswd(file)
        UI_Utils.doLogin(driver, username, password)
        wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, 'xos-nav')))

        searchbar = driver.find_element_by_css_selector('xos-header .navbar-form > input')
        searchbar.send_keys('node')

        dropdown = driver.find_element_by_css_selector('.navbar-form > .dropdown-menu')
        search_results = dropdown.find_elements_by_css_selector('li')
        assert len(search_results) == 4

        search_results.sendKeys(Keys.RETURN)
        time.sleep(1)
        print driver.current_url
        assert driver.current_url is not url + '/'

        UI_Utils.tearDown(driver)

if __name__ == "__main__":
    homepage.testHomePageElements(
        '../../../../../build/platform-install/credentials/xosadmin@opencord.org',
        'http://xos.dev/spa/#',
        'xosadmin@opencord.org'
    )
