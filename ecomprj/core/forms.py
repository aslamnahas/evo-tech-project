from django import forms
from .models import Banner,Review   

class BannerForm(forms.ModelForm):
    class Meta:
        model = Banner
        fields = ['image', 'title', 'description', 'url', 'deleted']



class ReviewForm(forms.ModelForm):
    class Meta:
        model = Review
        fields = ['rating', 'comment']