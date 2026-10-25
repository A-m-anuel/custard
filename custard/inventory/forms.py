from __future__ import annotations

from django import forms
from django.contrib.auth import get_user_model

from custard.catalog.models import AssetCategory, AssetType

from .models import Asset


def grouped_category_choices(queryset=None):
    queryset = queryset if queryset is not None else AssetCategory.objects.filter(is_active=True)
    queryset = queryset.select_related("asset_type")
    groups = []
    for asset_type in AssetType.objects.all():
        options = [(c.pk, c.name) for c in queryset if c.asset_type_id == asset_type.pk]
        if options:
            groups.append((asset_type.name, options))
    return [("", "Select a category")] + groups


def user_choices():
    return get_user_model().objects.filter(is_active=True).order_by("username")


class AssetForm(forms.ModelForm):
    class Meta:
        model = Asset
        fields = ["name", "category", "description", "owner", "location",
                  "impact_confidentiality", "impact_integrity", "impact_availability"]
        widgets = {"description": forms.Textarea(attrs={"rows": 3})}
        help_texts = {
            "impact_confidentiality": "Harm if the asset's information is disclosed.",
            "impact_integrity": "Harm if the asset or its data is altered.",
            "impact_availability": "Harm if the asset is unavailable.",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        active = AssetCategory.objects.filter(is_active=True)
        if self.instance.pk:  # keep a now-inactive current category selectable
            active = active | AssetCategory.objects.filter(pk=self.instance.category_id)
        self.fields["category"].queryset = active.distinct()
        self.fields["category"].choices = grouped_category_choices(active.distinct())
        self.fields["owner"].queryset = user_choices()
        self.fields["owner"].empty_label = "Unassigned"
        self.fields["owner"].label_from_instance = lambda u: u.get_full_name() or u.get_username()

    def clean_name(self):
        name = " ".join(self.cleaned_data["name"].split())
        duplicate = Asset.objects.filter(name__iexact=name).exclude(pk=self.instance.pk)
        if duplicate.exists():
            raise forms.ValidationError("An asset with this name already exists.")
        return name


class AssetCreateForm(AssetForm):
    """Registration form with the security checklist (rendered client-side for the chosen category)."""

    notes = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 2}),
                            label="Assessment notes")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.checklist_ids: list[int] | None = None
        if self.data:
            raw = self.data.getlist("checklist") if hasattr(self.data, "getlist") else []
            submitted = self.data.get("checklist_submitted") == "1"
            try:
                self.checklist_ids = [int(v) for v in raw] if submitted else None
            except ValueError:
                self.checklist_ids = []
                self._bad_checklist = True

    def clean(self):
        cleaned = super().clean()
        category = cleaned.get("category")
        if getattr(self, "_bad_checklist", False):
            raise forms.ValidationError("Invalid checklist submission.")
        if category and self.checklist_ids:
            valid = set(category.active_checklist().values_list("pk", flat=True))
            if not set(self.checklist_ids) <= valid:
                raise forms.ValidationError("The checklist does not belong to the selected category.")
        return cleaned


class AssessmentForm(forms.Form):
    notes = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 3}))

    def __init__(self, *args, asset: Asset, **kwargs):
        super().__init__(*args, **kwargs)
        self.items = list(asset.category.active_checklist())
        self.fields["checklist"] = forms.TypedMultipleChoiceField(
            choices=[(item.pk, item.text) for item in self.items], coerce=int, required=False,
            widget=forms.CheckboxSelectMultiple,
        )

    def items_by_pillar(self, checked: set[int]):
        from custard.core.choices import Pillar

        groups = []
        for value, label in Pillar.choices:
            items = [(i, i.pk in checked) for i in self.items if i.pillar == value]
            if items:
                groups.append((label, items))
        return groups


class AssetImportForm(forms.Form):
    file = forms.FileField(help_text="UTF-8 CSV, up to 2 MB.")
    dry_run = forms.BooleanField(required=False, initial=True, label="Validate only (do not import)")

    def clean_file(self):
        f = self.cleaned_data["file"]
        if not f.name.lower().endswith(".csv"):
            raise forms.ValidationError("Upload a .csv file.")
        if f.size > 2 * 1024 * 1024:
            raise forms.ValidationError("The file is larger than 2 MB.")
        return f
