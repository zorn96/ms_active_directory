# Created in August 2021
#
# Author: Azaria Zornberg
#
# Copyright 2021 - 2021 Azaria Zornberg
#
# This file is part of ms_active_directory
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import logging

_ad_logger = None


def configure_log_level(level: str):
    """ Set the log level of the AD logger
    :param level: The lowest log severity to be recorded.
    """
    get_logger().setLevel(level)


def disable_logging():
    """ Disable logging entirely for the AD logger """
    get_logger().propagate = False


def enable_logging():
    """ Enable logging for the AD logger """
    get_logger().propagate = True


def get_logger():
    """ Retrieve the AD logger for this package. If it has not been declared, then declare it. """
    global _ad_logger
    if _ad_logger is not None:
        return _ad_logger
    logger = logging.getLogger('ms_active_directory')
    # by default, only log info+
    logger.setLevel(logging.INFO)
    _ad_logger = logger
    return _ad_logger
