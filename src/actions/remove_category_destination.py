# Copyright (c) 2026 Splunk Inc.
# Licensed under the Apache License, Version 2.0
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client
from ._validators import validate_web_destination

logger = getLogger()


class RemoveCategoryDestinationParams(Params):
    category_id: str = Param(
        description="The ID of the custom category to update",
        primary=True,
        cef_types=["zscaler url category"],
    )
    destinations: str | None = Param(
        description="Comma-separated destinations to remove from the category",
        primary=True,
        cef_types=["url", "domain", "ip", "ipv6", "url list"],
        allow_list=True,
        default=None,
    )
    retaining_parent_category_destinations: str | None = Param(
        description="Comma-separated destinations to remove from the retaining-parent-category list",
        primary=True,
        cef_types=["url", "domain", "ip", "ipv6", "url list"],
        allow_list=True,
        default=None,
    )


class ScopesOutput(PermissiveActionOutput):
    Type: str | None = None


class RemoveCategoryDestinationOutput(PermissiveActionOutput):
    id: str | None = None
    val: float | None = None
    type: str | None = None
    urls: list[str] | None = None
    scopes: list[ScopesOutput] | None = None
    editable: bool | None = None
    keywords: list[str] | None = None
    description: str | None = None
    configuredName: str | None = None
    customCategory: bool | None = None
    customUrlsCount: float | None = None
    dbCategorizedUrls: list[str] | None = None
    customIpRangesCount: float | None = None
    keywordsRetainingParentCategory: list[str] | None = None
    urlsRetainingParentCategoryCount: float | None = None
    ipRangesRetainingParentCategoryCount: float | None = None


def remove_category_destination(
    params: RemoveCategoryDestinationParams, soar: SOARClient, asset: Asset
) -> RemoveCategoryDestinationOutput:
    values = [
        item.strip() for item in (params.destinations or "").split(",") if item.strip()
    ]
    parent_values = [
        item.strip()
        for item in (params.retaining_parent_category_destinations or "").split(",")
        if item.strip()
    ]
    try:
        if not values and not parent_values:
            raise ValueError(
                "Provide at least one value in destinations or retaining_parent_category_destinations"
            )
        destinations: list[str] = []
        for value in values:
            destination = validate_web_destination(value)
            if destination not in destinations:
                destinations.append(destination)
        parent_destinations: list[str] = []
        for value in parent_values:
            destination = validate_web_destination(value)
            if destination not in parent_destinations:
                parent_destinations.append(destination)
    except ValueError as exc:
        message = str(exc)
        soar.set_message(message)
        raise ActionFailure(message) from exc

    try:
        with get_client(asset) as client:
            category, response, error = client.zia.url_categories.get_category(
                params.category_id
            )
            if error is not None:
                raise RuntimeError(f"Zscaler API error: {error}")
            if category is None or response is None:
                raise RuntimeError("Zscaler API returned no category")
            raw_category = response.get_body()
            if not isinstance(raw_category, dict):
                raise RuntimeError("Zscaler API returned an invalid category")
            if not raw_category.get("customCategory", False):
                raise RuntimeError(
                    f"Category with {params.category_id} is a default category, which cannot be modified"
                )
            configured_name = raw_category.get("configuredName")
            if not isinstance(configured_name, str):
                raise RuntimeError("Zscaler API returned a category without a name")
            updated, updated_response, error = (
                client.zia.url_categories.delete_urls_from_category(
                    params.category_id,
                    configuredName=configured_name,
                    urls=destinations,
                    dbCategorizedUrls=parent_destinations,
                )
            )
            if error is not None:
                raise RuntimeError(f"Zscaler API error: {error}")
            if updated is None or updated_response is None:
                raise RuntimeError("Zscaler API returned no updated category")
            raw_updated = updated_response.get_body()
            if not isinstance(raw_updated, dict):
                raise RuntimeError("Zscaler API returned an invalid updated category")
            result = RemoveCategoryDestinationOutput(**raw_updated)
            activation, _response, error = client.zia.activate.activate()
            if error is not None or activation is None:
                detail = error or "Zscaler API returned no activation data"
                raise RuntimeError(
                    f"The category change was saved but could not be activated and is not yet enforced. {detail}"
                )
    except Exception as exc:
        logger.exception("Remove category destination failed")
        message = f"Remove category destination failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc
    soar.set_message("Category destinations removed")
    return result
