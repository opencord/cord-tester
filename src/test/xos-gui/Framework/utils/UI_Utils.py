import unittest
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import sys
import time


class UI_Utils(object):

    url = 'http://xos.dev/spa/#'
    driver = None

    @staticmethod
    def setUp():
        driver = webdriver.PhantomJS()

        driver.set_window_size(1920, 1280)
        return driver

    @staticmethod
    def tearDown(driver):
        driver.quit()

    @staticmethod
    def getPasswd(file):
        f = open(file)
        lines = f.readlines()
        f.close()
        return lines[0]

    @staticmethod
    def doLogin(driver, username, password):
        driver.get(UI_Utils.url + '/login')
        username_field = driver.find_element_by_css_selector('#username')
        password_field = driver.find_element_by_css_selector('#password')
        sign_in_field = driver.find_element_by_css_selector('.btn.btn-accent')

        username_field.send_keys(username)
        password_field.send_keys(password)
        sign_in_field.click()
        time.sleep(1)
