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
