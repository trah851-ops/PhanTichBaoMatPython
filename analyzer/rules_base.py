class BaseRule:
    id = "base"
    type = "general"
    severity = "medium"

    def check_assign(self, node, engine):
        pass

    def check_call(self, node, engine):
        pass

    def check_import(self, node, engine):
        pass

    def check_import_from(self, node, engine):
        pass

    def check_function(self, node, engine):
        pass

    def check_class(self, node, engine):
        pass
