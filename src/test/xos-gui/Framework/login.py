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


class login():
    """Test cases for XOS"""

    @staticmethod
    def testLoginPage(file, url, username, password):

        if password == 'real_pwd':
            pwd = UI_Utils.getPasswd(file)
        else:
            pwd = password

        driver = UI_Utils.setUp()
        wait = WebDriverWait(driver, 10)
        driver.get(UI_Utils.url + '/login')
        login_component = driver.find_element_by_css_selector('xos-login')
        assert login_component, "Login component is missing"
        username_field = driver.find_element_by_css_selector('#username')
        password_field = driver.find_element_by_css_selector('#password')
        sign_in_field = driver.find_element_by_css_selector('.btn.btn-accent')

        username_field.send_keys(username)
        password_field.send_keys(pwd)
        sign_in_field.click()

        if password == 'real_pwd':
            wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, 'xos-nav')))
            assert 'login' not in driver.current_url, "Login Failed"
        else:
            wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, '.alert.alert-danger')))
            error = driver.find_element_by_css_selector('.alert.alert-danger')
            assert error.is_displayed()

        UI_Utils.tearDown(driver)

if __name__ == "__main__":
    login.testLoginPage(
        '../../../../../build/platform-install/credentials/xosadmin@opencord.org',
        'http://xos.dev/spa/#',
        'xosadmin@opencord.org',
        'real_pwd')
