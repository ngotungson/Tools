import os
from helpers.action_logger import ActionLogger
from datalayer.flask_extension import Datalayer, DataStore

action_logger = ActionLogger()
records_store = DataStore()
records = Datalayer()
records_tenant = TenantDatalayer()
APP_DIRECTORY = os.path.dirname(os.path.realpath(__file__))



class TenantDatalayer(Datalayer):
    def __init__(self):
        pass

    @staticmethod
    def _get_tenant(self):
        return "sonnt78"

    def filter_by_query_string(self, tenant, table, query_string, **kwargs):
        tenant = self._get_tenant()
        query_string =  query_string + " AND " + "tenant = {}".format(tenant)
        return super(TenantDatalayer, self).filter_by_query_string(self, tenant, table, query_string, **kwargs)