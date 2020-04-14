from flask import jsonify
import datetime
from soar_api.extensions import action_logger
from soar_api.logger import Action
from soar_api.extensions import records, records_tenant
from flask import current_app
import soar_api.api_error as api_error
from soar_api.utils import get_time
from soar_api.rest import add_user_update, ActorAPI

from datalayer.flask_extension import DataStore
from soar_api.alert_mapping import AlertMapping
from scripts.model import Alert, Case


TABLE = "alert"

STATUS_LIST = [Alert.Status.OPEN, Alert.Status.CLOSE]


def search_alert(tenant, body=None):
    """
    api get search alert
    :return:
    """
    status, alert_group, error = records_tenant.filter_by_query_string(
        tenant=tenant,
        table=TABLE,
        query_string=body.get("query", ""),
        offset=body.get("_from", 0),
        limit=body.get("_size", 10),
        order_by=body.get("_sort", None),
    )

    ret = {"data": [], "count": 0}

    if status == DataStore.OK:
        ret["data"] = alert_group
    else:
        current_app.logger.error(error)
        raise api_error.InternalServerError()

    if not body.get("_counting", False):
        return jsonify(ret)

    status, count, error = records_tenant.count_by_query_string(
        tenant=tenant, table=TABLE, query_string=body.get("query", "")
    )

    if status == DataStore.OK:
        ret["count"] = count
    else:
        current_app.logger.error(error)
        raise api_error.InternalServerError()

    return jsonify(ret)


def get_statistic_alert(tenant, body=None):
    """
    api get statistic alerts ==> API này viết như này không tổng quát ==> sửa sau.
    :return:
    """
    count_dict = {
        "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "status": {
            "open": 0,
            "close": 0,
            # "false positive": 0,
            # "done": 0,
        },
    }

    query = body.get("query")
    if query:
        query = "({}) AND ".format(query)

    for key in count_dict:
        for value in count_dict[key]:
            count_query = '{} {} = "{}"'.format(query, key, value)
            status, data, error = records.count_by_query_string(
                tenant=tenant, table=TABLE, query_string=count_query
            )
            if status != DataStore.OK:
                raise api_error.InternalServerError()
            count_dict[key][value] = data

    # for sla
    sla = {"overdue": 0, "on_time": 0, "active": 0}

    count_query = "{} sla_expired = TRUE".format(query)
    status, data, error = records.count_by_query_string(
        tenant=tenant, table=TABLE, query_string=count_query
    )
    if status != DataStore.OK:
        raise api_error.InternalServerError()
    sla["overdue"] = data

    count_query = '{} status = "close" AND sla_expired = FALSE'.format(query)
    status, data, error = records.count_by_query_string(
        tenant=tenant, table=TABLE, query_string=count_query
    )
    if status != DataStore.OK:
        raise api_error.InternalServerError()
    sla["on_time"] = data

    count_query = '{} status != "close" AND sla_expired = FALSE'.format(query)
    status, data, error = records.count_by_query_string(
        tenant=tenant, table=TABLE, query_string=count_query
    )
    if status != DataStore.OK:
        raise api_error.InternalServerError()
    sla["active"] = data

    count_dict["sla"] = sla

    return count_dict


def get_alert(tenant, _id=None):
    """
    api get alert by id
    :return:
    """
    status, alert, error = records.get(tenant=tenant, table=TABLE, _id=_id)
    if status == DataStore.OK:
        ret = {"data": alert}
        return jsonify(ret)
    else:
        raise api_error.InvalidParameter(
            error_code=4001002, params="_id", payload={"error_prams": "_id"}
        )


def info_alert(tenant, _id):
    """

    :return: add more info alert to prepare escalate to case
    """
    status, alert, error = records.get(tenant=tenant, table=TABLE, _id=_id)
    if alert:
        sub_category = alert.get("sub_category", "")
        organization_group = alert.get("organization_group", "")
        description = alert.get("description_en", alert.get("description"))
        message = alert.get("message_en", alert.get("message", ""))
        incident_desc = (
            ""
            "*** Alert [{0}]\n"
            "Time: {1}\n"
            "Message: {2}\n"
            "Detail: {3}\n"
            "Log source: {4}\n"
            "Type: {5}\n"
            "Sub Category: {6}\n"
            "Object: {7}\n"
            "Object type: {8}\n"
            "***"
        )
        incident_title = "[{0}][{1}: {2}] {3}"
        if alert.get("source_log") == "se":
            if alert.get("category") not in ("AUTO_ITEM", "CONF_ITEM"):
                incident_title = incident_title.format(
                    alert.get("source_log", ""),
                    alert.get("object_type", ""),
                    alert.get("object", ""),
                    description,
                )
            else:
                incident_title = incident_title.format(
                    alert.get("source_log", ""),
                    alert.get("object_type", ""),
                    alert.get("object", ""),
                    message,
                )
        elif alert.get("source_log") in ("netad_office", "netad_server"):
            incident_title = incident_title.format(
                alert.get("source_log", ""),
                alert.get("object_type", ""),
                alert.get("object", ""),
                description,
            )
        else:
            incident_title = incident_title.format(
                alert.get("source_log", ""),
                alert.get("object_type", ""),
                alert.get("object", ""),
                message,
            )
        incident_severity = alert.get("severity")

        def tagize(s):
            if isinstance(s, str):
                return s.lower().replace(" ", "_")
            else:
                return ""

        incident_tags = ",".join(
            [
                tagize(alert.get("source_log")),
                tagize(alert.get("type")),
                tagize(sub_category),
                tagize(alert.get("rule_id")),
                tagize(organization_group),
            ]
        )

        alert["case_title"] = incident_title
        alert["case_desc"] = incident_desc.format(
            alert.get("alert_id", ""),
            datetime.datetime.fromtimestamp(int(alert.get("created") / 1000)).strftime(
                "%H:%M:%S %d-%m-%Y"
            ),
            message,
            description,
            alert.get("source_log", ""),
            alert["type"],
            sub_category,
            alert.get("object", ""),
            alert.get("object_type", ""),
        )
        alert["case_severity"] = incident_severity
        alert["case_tags"] = incident_tags

        return jsonify({"data": alert})
    else:
        raise api_error.InvalidParameter(
            error_code=4001002, params="_id", payload={"error_prams": "_id"}
        )


@add_user_update
def create_alert(tenant, body=None):
    """
    api insert alert to postgres
    :return:
    """
    action_logger.info(action=Action.ALERT_CREATE, state=Action.STATE_START)

    # modify params new alert
    body["status"] = Alert.Status.OPEN
    body["unread"] = True
    body["created"] = get_time()
    body["sla_expired"] = False

    # remove if body have id conflict id auto increment in db
    if body.get("_id") or body.get("_id") == 0:
        body["_alert_id"] = body["_id"]
        del body["_id"]

    # if body.get("status", None) is not None and body['status'] not in STATUS_LIST:
    #     raise api_error.InvalidParameter(error_code=4001000, params="status",
    #                                      payload={"error_prams": "status"})

    # check severity
    SEVERITY_LIST = [
        Alert.Severity.LOW,
        Alert.Severity.MEDIUM,
        Alert.Severity.HIGH,
        Alert.Severity.CRITICAL,
    ]
    if body.get("severity") not in SEVERITY_LIST:
        raise api_error.InvalidParameter(
            error_code=4001000, params="severity", payload={"error_prams": "severity"}
        )

    status, result, error = records.create(tenant=tenant, table=TABLE, data=body)
    if status == DataStore.OK:
        ret = {"data": result}
        action_logger.info(action=Action.ALERT_CREATE, state=Action.STATE_SUCCESS)
        return jsonify(ret), 201
    else:
        action_logger.info(
            action=Action.ALERT_CREATE, error=error, state=Action.STATE_ERROR
        )
        current_app.logger.error(error)
        raise api_error.InternalServerError()


def normalized_alert(tenant, source, body):
    """
    func call lib normalized alert
    :return:
    """
    # current_app.logger.info(body)
    try:
        alert = AlertMapping.parser_raw_alert(
            tenant=tenant, source=source, raw_alert=body
        )
        return alert
    except Exception as e:
        current_app.logger.error(e)
        raise api_error.InternalServerError()


@add_user_update
def create_alert_raw(tenant, source, body=None):
    """
    api insert alert raw to postgres
    """
    alert = normalized_alert(tenant=tenant, source=source, body=body)
    alert[Alert.Attr.source] = source
    return create_alert(tenant, alert)


@add_user_update
def update_alert(tenant, _id=None, body=None):
    """
    api update alert to postgres
    update: status,...
    :return:
    """
    action_logger.info(action=Action.ALERT_UPDATE, _id=_id, state=Action.STATE_START)
    status, alert, error = records.get(tenant=tenant, table=TABLE, _id=_id)
    if not alert:
        raise api_error.InvalidParameter(error_code=4001002, params="_id")

    _remove_not_allowed_to_update_fields(body)

    # check severity
    SEVERITY_LIST = [
        Alert.Severity.LOW,
        Alert.Severity.MEDIUM,
        Alert.Severity.HIGH,
        Alert.Severity.CRITICAL,
    ]
    if body.get("severity") is not None and body.get("severity") not in SEVERITY_LIST:
        raise api_error.InvalidParameter(
            error_code=4001000, params="severity", payload={"error_prams": "severity"}
        )

    REASON_CLOSE_LIST = [
        Alert.ReasonClose.FALSE_POSITIVE,
        Alert.ReasonClose.ESCALATE_TO_CASE,
    ]

    if body.get("status", None) is not None and body["status"] not in STATUS_LIST:
        raise api_error.InvalidParameter(
            error_code=4001000, params="status", payload={"error_prams": "status"}
        )

    if (
        body.get("status") == Alert.Status.CLOSE
        and body.get("reason_close", "") not in REASON_CLOSE_LIST
    ):
        raise api_error.InvalidParameter(error_code=4001000, params="reason_close")

    if (
        body.get("status") == Alert.Status.CLOSE
        and body.get("reason_close") == Alert.ReasonClose.FALSE_POSITIVE
        and body.get("reason_false_positive") is None
    ):
        raise api_error.InvalidParameter(
            error_code=4001002, params="reason_false_positive"
        )

    status, alert, error = records.update(
        tenant=tenant, table=TABLE, _id=_id, data=body
    )
    if status == DataStore.OK:
        ret = {"data": alert}
        action_logger.info(
            action=Action.ALERT_UPDATE, _id=_id, state=Action.STATE_SUCCESS
        )
        return jsonify(ret)
    else:
        action_logger.info(
            action=Action.ALERT_UPDATE, _id=_id, error=error, state=Action.STATE_ERROR
        )
        current_app.logger.error(error)
        raise api_error.InternalServerError()


def _remove_not_allowed_to_update_fields(alert):
    for key, value in dict(alert).items():
        if key in ["_id", "alert_id", "created"]:
            del alert[key]
        if not ActorAPI().get_actor().startswith("system") and key in [
            "sla",
            "sla_expired",
        ]:
            del alert[key]


def delete_alert(tenant, _id=None):
    """
    delete alert by id
    :param tenant:
    :param _id:
    :return:
    """
    action_logger.info(action=Action.ALERT_DELETE, _id=_id, state=Action.STATE_START)
    status, alert, error = records.get(tenant=tenant, table=TABLE, _id=_id)
    if not alert:
        raise api_error.InvalidParameter(error_code=4001002, params="_id")
    status, alert, error = records.delete(tenant=tenant, table=TABLE, _id=_id)
    if status == DataStore.OK:
        ret = {}
        action_logger.info(
            action=Action.ALERT_DELETE, _id=_id, state=Action.STATE_SUCCESS
        )
        return jsonify(ret), 204
    else:
        action_logger.info(
            action=Action.ALERT_DELETE, _id=_id, state=Action.STATE_ERROR
        )
        current_app.logger.error(error)
        raise api_error.InternalServerError()


def get_activity_logs_alert(tenant, _id=None):
    """
    get activity logs of a alert
    :param tenant:
    :param _id:
    :return:
    """
    status, alert, error = records.get(tenant=tenant, table=TABLE, _id=_id)
    if not alert:
        raise api_error.InvalidParameter(error_code=4001002, params="_id")

    query_string = (
        '(target_type = IN(["alerts", "alert"]) AND target_id = {0}) '
        'OR (target_type = "audit_log" AND (data._alerts_id = {0} OR data._alert_id = {0}))'.format(
            _id
        )
    )
    status, log_group, error = records.list_event(
        tenant=tenant,
        target_type="alert,audit_log",
        sort="time_stamp",
        query_string=query_string,
    )

    print(error)
    if status == DataStore.OK:
        ret = {"data": log_group}
        return jsonify(ret)
    else:
        current_app.logger.error(error)
        import traceback

        current_app.logger.error(traceback.print_exc(limit=20))
        raise api_error.InternalServerError()


def link_to_case(tenant, _id_alert, _id_case):
    """
    link alert to exists case
    :param tenant:
    :param _id_alert:
    :param _id_case:
    :return:
    """
    # check alert exist
    status, alert, error = records.get(tenant=tenant, table=TABLE, _id=_id_alert)
    if not alert:
        raise api_error.InvalidParameter(error_code=4001002, params="_id_alert")

    # check alert status
    if alert.get(Alert.Attr.status) == Alert.Status.CLOSE:
        raise api_error.InvalidParameter(
            error_code=4001000,
            params="_id_alert",
            payload={"status error": alert.get(Alert.Attr.status)},
        )

    # check case if exist
    from soar_api.rest.cases import get_case

    response = get_case(tenant=tenant, _id=_id_case)
    if not response.json["data"]:
        raise api_error.InvalidParameter(error_code=4001002, params="_id_case")
    case = response.json["data"]
    if case.get("status") == Case.Status.CLOSE:
        body_update_case = {"status": Case.Status.OPEN}
        from soar_api.rest.cases import update_case

        response = update_case(tenant=tenant, _id=case["_id"], body=body_update_case)
        if response.status_code != 200:
            return response

    # update alert
    body_update_alert = {
        "linked_case": case["case_id"],
        "status": Alert.Status.CLOSE,
        "reason_close": Alert.ReasonClose.ESCALATE_TO_CASE,
    }
    return update_alert(tenant, _id=_id_alert, body=body_update_alert)


def escalate_to_case(tenant, _id, body):
    """
    escalate a alert to case
    :param tenant:
    :param _id:
    :param body:
    :return:
    """
    # check alert exist
    status, alert, error = records.get(tenant=tenant, table=TABLE, _id=_id)
    if not alert:
        raise api_error.InvalidParameter(error_code=4001002, params="_id")

    # check alert status
    if alert.get(Alert.Attr.status) == Alert.Status.CLOSE:
        raise api_error.InvalidParameter(
            error_code=4001000,
            params="_id_alert",
            payload={"status error": alert.get(Alert.Attr.status)},
        )

    # create case
    from soar_api.rest.cases import create_case

    res_create, status = create_case(tenant=tenant, body=body)
    if status != 201:
        return res_create
    case = res_create.json["data"]
    case_id = case["case_id"]

    body_update_alert = {
        "linked_case": case_id,
        "status": Alert.Status.CLOSE,
        "reason_close": Alert.ReasonClose.ESCALATE_TO_CASE,
    }
    res_update = update_alert(tenant, _id=_id, body=body_update_alert)
    if res_update.status_code != 200:
        return res_update
    return res_create
