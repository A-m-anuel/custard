from __future__ import annotations

from django import forms

from custard.core.choices import Level, Pillar

from .models import AssetCategory, AssetType, ChecklistItem, Vulnerability

LINES_HELP = "One item per line."


def _lines(value: str) -> list[str]:
    seen, out = set(), []
    for line in (value or "").splitlines():
        text = " ".join(line.split())[:255]
        if text and text.lower() not in seen:
            seen.add(text.lower())
            out.append(text)
    return out


class CategoryCreateForm(forms.ModelForm):
    """Custom asset category with its CIA checklist (fixes dissertation test case 6)."""

    confidentiality = forms.CharField(widget=forms.Textarea(attrs={"rows": 4}), required=False, help_text=LINES_HELP,
                                      label="Confidentiality checks")
    integrity = forms.CharField(widget=forms.Textarea(attrs={"rows": 3}), required=False, help_text=LINES_HELP,
                                label="Integrity checks")
    availability = forms.CharField(widget=forms.Textarea(attrs={"rows": 3}), required=False, help_text=LINES_HELP,
                                   label="Availability checks")

    class Meta:
        model = AssetCategory
        fields = ["asset_type", "name", "description"]
        widgets = {"description": forms.Textarea(attrs={"rows": 2})}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["asset_type"].queryset = AssetType.objects.all()

    def clean_name(self):
        name = " ".join(self.cleaned_data["name"].split())
        if AssetCategory.objects.filter(name__iexact=name).exists():
            raise forms.ValidationError("A category with this name already exists.")
        return name

    def checklist(self) -> list[tuple[str, str]]:
        items = []
        for pillar, field in ((Pillar.CONFIDENTIALITY, "confidentiality"), (Pillar.INTEGRITY, "integrity"),
                              (Pillar.AVAILABILITY, "availability")):
            items += [(pillar.value, text) for text in _lines(self.cleaned_data.get(field, ""))]
        return items

    def clean(self):
        cleaned = super().clean()
        if not self.errors and not self.checklist():
            raise forms.ValidationError("Add at least one checklist item so assets in this category can be scored.")
        return cleaned


class ChecklistItemForm(forms.ModelForm):
    class Meta:
        model = ChecklistItem
        fields = ["text", "pillar", "reference"]

    def __init__(self, *args, category: AssetCategory, **kwargs):
        super().__init__(*args, **kwargs)
        self.category = category

    def clean_text(self):
        text = " ".join(self.cleaned_data["text"].split())
        if self.category.checklist_items.filter(text__iexact=text).exists():
            raise forms.ValidationError("This check already exists for the category.")
        return text


class DefaultVulnerabilityForm(forms.Form):
    vulnerability = forms.ModelChoiceField(queryset=Vulnerability.objects.all(), required=False,
                                           empty_label="Choose from the library")
    new_vulnerability = forms.CharField(max_length=150, required=False, label="…or name a new weakness")
    likelihood = forms.ChoiceField(choices=Level.choices, initial=Level.MEDIUM)
    mitigations = forms.CharField(widget=forms.Textarea(attrs={"rows": 3}), required=False,
                                  help_text="Recommended mitigations for this category, one per line.")

    def __init__(self, *args, category: AssetCategory, **kwargs):
        super().__init__(*args, **kwargs)
        self.category = category
        self.fields["vulnerability"].queryset = Vulnerability.objects.exclude(category_links__category=category)

    def clean(self):
        cleaned = super().clean()
        vuln, new = cleaned.get("vulnerability"), (cleaned.get("new_vulnerability") or "").strip()
        if not vuln and not new:
            raise forms.ValidationError("Choose a weakness or name a new one.")
        if not vuln and self.category.default_vulnerabilities.filter(vulnerability__name__iexact=new).exists():
            raise forms.ValidationError("This weakness is already mapped to the category.")
        return cleaned

    def mitigation_names(self) -> list[str]:
        return _lines(self.cleaned_data.get("mitigations", ""))
