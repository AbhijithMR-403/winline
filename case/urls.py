from .views import *
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import FileUploadViewSet

router = DefaultRouter()
router.register(r'upload', FileUploadViewSet, basename='fileupload')

urlpatterns = [
    path('fund-management/', fund_management, name='fund_management'),
    path('update-case-status/<int:case_id>/', update_case_status, name='update_case_status'),
    path('update-repayment-status/<int:case_id>/', update_repayment_status, name='update_repayment_status'),
    path('track-repayment/<int:case_id>/', track_repayment, name='track_repayment'),
    path('track-disbursement/<int:case_id>/', track_disbursement, name='track_disbursement'),
    path('update-repayment/<int:case_id>/', update_case_repayment, name='update_case_repayment'),
    path('get-repayment/', get_case_repayment, name='get_case_repayment'),
    path('update-disbursement/<int:case_id>/', update_case_disbursement, name='update_case_disbursement'),
    path('get-disbursement/', get_case_disbursement, name='get_case_disbursement'),
    path('ask-query/<int:case_id>/', get_ask_query, name='get_ask_query'),
    path('answer-query/<int:case_id>/', get_answer_query, name='get_answer_query'),
    path('update-case-details/<int:case_id>/', update_case_details, name='update_case_details'),
    path('case-details/', get_case_details, name='get_case_details'),
    path('search-case/', get_search_case, name='get_search_case'),
    path('search-user/', get_search_user, name='get_search_user'),
    path('get-case-list/', get_case_list, name='get_case_list'),
    path('purpose-details/', get_purpose_details, name='get_purpose_details'),
    path('create-case/', create_case, name='create_case'),
    path('create-case-31may/', create_case_31may, name='create_case_31may'),
    #path('upload/', ImageUploadView.as_view(), name='file-upload'),
    path('', include(router.urls)),

]