from django.contrib import admin

# Register your models here.
from .models import Case, CaseQuery, CasePurpose, CaseEvaluation, LovSeedData, CaseDisbursement, CaseRepayment, FileUpload


class FileUploadAdmin(admin.ModelAdmin):
  list_display = ("id", "file")

admin.site.register(FileUpload, FileUploadAdmin)

class CaseAdmin(admin.ModelAdmin):
  #ordering = ('id','case_id',)  # Default ordering in admin list view
  list_display = ("id","request_amt","approval_status", "guarantor_name",  "guarantor_phone", "guarantor_email", "purpose","approved_amt","disbursement_count","repay_plan","repayment_count","repay_percent")

admin.site.register(Case, CaseAdmin)

class CaseQueryAdmin(admin.ModelAdmin):
  list_display = ("id", "case_id", "question_text","answer_text", "supp_docs_list",  "question_by", "answer_by","question_time", "state")

admin.site.register(CaseQuery, CaseQueryAdmin)

class CasePurposeAdmin(admin.ModelAdmin):
  list_display = ("id", "case_id", "purpose_name","question_text", "answer_text",  "created_at")

admin.site.register(CasePurpose, CasePurposeAdmin)

class CaseEvaluationAdmin(admin.ModelAdmin):
  list_display = ("id", "case_id", "user_type","evaluator_notes", "evaluation_status", "case_id","user_id")

admin.site.register(CaseEvaluation, CaseEvaluationAdmin)

class DisbursementAdmin(admin.ModelAdmin):
  list_display = ("id", "case_id", "created_by","created_time", "installment_amt", "planned_date", "disbursed_date", "disbursed_amt", "remaining_amt", "tot_disbursed_amt", "disbursement_status")

admin.site.register(CaseDisbursement, DisbursementAdmin)

class RepaymentAdmin(admin.ModelAdmin):
  list_display = ("id", "case_id", "created_by","created_time", "planned_repayment_amt", "planned_date", "repayment_date", "actual_repayment_amt", "outstanding_amt", "tot_repayed_amt", "repayment_status")

admin.site.register(CaseRepayment, RepaymentAdmin)

class LovSeedDataAdmin(admin.ModelAdmin):
  list_display = ("lov","lov_parent_code","lov_code", "display_label",  "input_type", "lov_ref_code", "mandatory", "status")

admin.site.register(LovSeedData, LovSeedDataAdmin)