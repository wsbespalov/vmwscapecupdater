from __future__ import unicode_literals

from django.db import models
from django.utils import timezone
from django.contrib.postgres.fields import ArrayField


class VULNERABILITY_CAPEC:
    class Meta:
        ordering = ['capec_id', "modification"]
        verbose_name = 'vulnerability_capec'
        verbose_name_plural = 'vulnerability_capec'

    id = models.BigAutoField(primary_key=True)
    capec_id = models.TextField(default="")
    name = models.TextField(default="")
    summary = models.TextField(default="")
    prerequisites = models.TextField(default="")
    solutions = models.TextField(default="")
    # CWE
    related_weakness = ArrayField(models.TextField(blank=True), default=list)
    created = models.DateTimeField(default=timezone.now)
    modification = models.IntegerField(default=0)
    objects = models.Manager()

    def __str__(self):
        return "{}".format(self.capec_id)

    def __unicode__(self):
        return "CAPEC: {}".format(self.capec_id)
    