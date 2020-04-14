import os
from helpers.action_logger import ActionLogger
from datalayer.flask_extension import Datalayer, DataStore

action_logger = ActionLogger()
records_store = DataStore()
records = Datalayer()
records_tenant = TenantDatalayer()
APP_DIRECTORY = os.path.dirname(os.path.realpath(__file__))

TABLES_BASED_ON_TENANT = ['alert']

class TenantDatalayer(Datalayer):
    def __init__(self):
        pass

    def _get_tenant_from_token(self):
        return "sonnt78"

    def _get_tenant_master(self):
        return "datpm1"

    def _add_tenant_to_query_string(self, query_string):
        tenant = self._get_tenant_from_token()
        tenant_master = self._get_tenant_master()
        # Neu tenant la master thi se khong gioi han tim kiem theo tenant
        if tenant == tenant_master:
            return query_string

        # Them dieu kien AND tenant cho cau query
        if query_string == "":
            query_string =  query_string + " AND " + 'tenant = "{}"'.format(tenant)
        else:
            query_string = 'tenant = "{}"'.format(tenant)

        return query_string


    def filter_by_query_string(self, remote_tenant, table, query_string, **kwargs):
        if table in TABLES_BASED_ON_TENANT:
            query_string = self._add_tenant_to_query_string(query_string)

        return super().filter_by_query_string(remote_tenant, table, query_string, **kwargs)


    def count_by_query_string(self, remote_tenant, table, query_string, **kwargs):
        if table in TABLES_BASED_ON_TENANT:
            query_string = self._add_tenant_to_query_string(query_string)

        return super().filter_by_query_string(remote_tenant, table, query_string, **kwargs)


    def create(self, remote_tenant, table, data, notify=True, commit=True):
        def _add_tenant_to_data():
            if table in TABLES_BASED_ON_TENANT:
                tenant = self._get_tenant_from_token()
                tenant_master = self._get_tenant_master()
                if tenant == tenant_master:
                    return data

                data.update({'tenant': tenant})
                return data

        data = _add_tenant_to_data(data)
        return super().create(remote_tenant, table, data, notify, commit)