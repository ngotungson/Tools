import os
import logging
import logging.config
import connexion

from werkzeug.exceptions import default_exceptions
from flask_cors import CORS
from .api_exception import APIException, handle_api_exception

from .utils import load_config
from soar_api.extensions import action_logger
from soar_api.extensions import records, records_store, records_tenant

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
APPLICATION_ROOT = os.path.join(MODULE_DIR, "..")


def create_app(config=None):
    """ Create an Flask application instance.

    :param config:
    :return:
    """

    app_config = config
    if app_config is None:
        config_file = os.path.join(APPLICATION_ROOT, "config.yaml")
        if os.path.isfile(config_file):
            app_config = load_config(config_file)
        else:
            raise Exception("No valid configuration found")

    swagger_file = app_config.get("SWAGGER_FILE_PATH")

    if swagger_file:
        swagger_dir, swagger_filename = os.path.split(swagger_file)
        app = connexion.App(__name__, specification_dir=swagger_dir)
        app.add_api(swagger_filename)

    else:
        raise Exception("SWAGGER_FILE_PATH is required in configuration file.")

    flask_app = app.app
    flask_app.config.from_mapping(app_config)
    flask_app.instance_path = MODULE_DIR

    configure_app(flask_app)
    configure_api_key(flask_app)

    return flask_app


def configure_app(app):
    """
    Configure a Flask app
    :param app:
    :param filename:
    :return:t
    """
    app.config["APPLICATION_ROOT"] = os.path.normpath(os.path.join(MODULE_DIR, ".."))

    CORS(app)
    configure_log_handlers(app)
    configure_extensions(app)
    configure_exception_handlers(app)


def configure_api_key(app):
    """
    Configure a api key
    :param app:
    :param filename:
    :return:t
    """
    path_api_key = os.path.join(APPLICATION_ROOT, "api-key.yaml")
    if os.path.isfile(path_api_key):
        api_key = load_config(path_api_key)
        app.config["API_KEY"] = api_key["KEY"]
    else:
        raise Exception("No valid api-key found")


def configure_log_handlers(app):
    """
    Config log
    :param app: flask app
    :return: not return
    """
    logging.config.fileConfig(app.config["LOGGER_CONFIG_PATH"])

    logger = logging.getLogger("root")

    # unify log format for all handers
    for h in logger.root.handlers:
        app.logger.addHandler(h)
    app.logger.setLevel(logger.root.level)

    app.logger.info("Start api services info log")
    app.logger.error("Start api services error log")


def configure_extensions(app):
    """
    :param app: flask app (main app)
    :return:
    """
    records_store.init_app(app=app, tis_version="future")
    records.create_from_datastore(records_store)
    records_tenant.create_from_datastore(records_store)
    # cache.init_app(app=app, config={'CACHE_TYPE': 'simple'})
    action_logger.init_app(app, logging.getLogger("action"))  # khởi tạo action_logger


def configure_exception_handlers(app):
    for exception in default_exceptions:
        app.register_error_handler(exception, handle_api_exception)
    app.register_error_handler(Exception, handle_api_exception)
