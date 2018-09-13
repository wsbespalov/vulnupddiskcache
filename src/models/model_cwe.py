import peewee

cwe_db_proxy = peewee.Proxy()


class VULNERABILITIES_CWE(peewee.Model):
    class Meta:
        database = cwe_db_proxy
        ordering = ("cwe_id", )
        table_name = "vulnerabilities_cwe"

    id = peewee.PrimaryKeyField(null=False, )
    cwe_id = peewee.TextField(default="", )
    name = peewee.TextField(default="", )
    status = peewee.TextField(default="", )
    weaknesses = peewee.TextField(default="", )
    description_summary = peewee.TextField(default="", )

    def __unicode__(self):
        return "vulnerabilities_cwe"

    def __str__(self):
        return str(self.cwe_id)

    @property
    def to_json(self):
        return dict(
            id=self.id,
            cwe_id=self.cwe_id,
            name=self.name,
            status=self.status,
            weaknesses=self.weaknesses,
            description_summary=self.description_summary
        )
