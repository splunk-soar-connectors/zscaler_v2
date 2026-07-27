# Zscaler v2

Publisher: Splunk <br>
Connector Version: 1.0.0 <br>
Product Vendor: Zscaler <br>
Product Name: Zscaler v2 <br>
Minimum Product Version: 7.0.0

This app implements containment and investigative actions for Zscaler Internet Access

### Configuration variables

This table lists the configuration variables required to operate Zscaler v2. These variables are specified when configuring a Zscaler v2 asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**vanity_domain** | required | string | Zscaler OneAPI vanity-domain prefix, for example 'dev-new-soar-splunk' rather than a full URL or email address |
**client_id** | required | string | OAuth client ID for the Zscaler OneAPI API client |
**client_secret** | required | password | OAuth client secret for the Zscaler OneAPI API client |
**cloud** | optional | string | Zscaler OneAPI cloud environment used to derive OAuth and API endpoints |
**sandbox_token** | optional | password | Optional ZIA Sandbox Submission API token required only by submit file |
**sandbox_cloud** | optional | string | Optional ZIA Sandbox cloud name used with the Sandbox Submission API token |

### Supported Actions

[test connectivity](#action-test-connectivity) - Authenticate through OneAPI and read the ZIA configuration activation status. <br>
[get report](#action-get-report) - Fetch a sandbox report for the provided MD5 file hash <br>
[list url categories](#action-list-url-categories) - List all URL categories <br>
[block ip](#action-block-ip) - Block an IP <br>
[block url](#action-block-url) - Block a URL <br>
[unblock ip](#action-unblock-ip) - Unblock an IP <br>
[unblock url](#action-unblock-url) - Unblock a URL <br>
[allow ip](#action-allow-ip) - Add an IP address to the allowlist <br>
[allow url](#action-allow-url) - Add a URL to the allowlist <br>
[unallow ip](#action-unallow-ip) - Remove an IP address from the allowlist <br>
[unallow url](#action-unallow-url) - Remove a URL from the allowlist <br>
[lookup ip](#action-lookup-ip) - Look up the categories related to an IP <br>
[lookup url](#action-lookup-url) - Look up the categories related to a URL <br>
[submit file](#action-submit-file) - Submit a file to Zscaler Sandbox <br>
[get admin users](#action-get-admin-users) - Get a list of admin users <br>
[get users](#action-get-users) - Get users, optionally filtered by name, department, or group <br>
[get groups](#action-get-groups) - Get a list of groups <br>
[add group user](#action-add-group-user) - Add a user to a group <br>
[remove group user](#action-remove-group-user) - Remove a user from a group <br>
[get allowlist](#action-get-allowlist) - Get URLs on the allowlist <br>
[get denylist](#action-get-denylist) - Get URLs on the denylist <br>
[update user](#action-update-user) - Update the user with the specified ID <br>
[add category url](#action-add-category-url) - Add URLs to a category <br>
[add category ip](#action-add-category-ip) - Add IPs to a category <br>
[remove category url](#action-remove-category-url) - Remove URLs from a category <br>
[remove category ip](#action-remove-category-ip) - Remove IPs from a category <br>
[create destination group](#action-create-destination-group) - Create a destination group <br>
[list destination group](#action-list-destination-group) - List destination groups <br>
[edit destination group](#action-edit-destination-group) - Edit a destination group <br>
[delete destination group](#action-delete-destination-group) - Delete destination groups <br>
[get departments](#action-get-departments) - Get a list of departments <br>
[get category details](#action-get-category-details) - Get the URLs and keywords of a category

## action: 'test connectivity'

Authenticate through OneAPI and read the ZIA configuration activation status.

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get report'

Fetch a sandbox report for the provided MD5 file hash

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file_hash** | required | The MD5 file hash | string | `md5` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.file_hash | string | `md5` | |
action_result.data.\*.Full Details.Classification.Category | string | | test BENIGN |
action_result.data.\*.Full Details.Classification.DetectedMalware | string | | |
action_result.data.\*.Full Details.Classification.Score | numeric | | 10 |
action_result.data.\*.Full Details.Classification.Type | string | | test BENIGN |
action_result.data.\*.Full Details.FileProperties.DigitalCerificate | string | | |
action_result.data.\*.Full Details.FileProperties.FileSize | numeric | | 350084 |
action_result.data.\*.Full Details.FileProperties.FileType | string | | test EXE |
action_result.data.\*.Full Details.FileProperties.Issuer | string | | |
action_result.data.\*.Full Details.FileProperties.MD5 | string | `md5` | test 1043ca3fc2e83f0c6f100e46d2ea16be |
action_result.data.\*.Full Details.FileProperties.RootCA | string | | |
action_result.data.\*.Full Details.FileProperties.SHA1 | string | `sha1` | test efbd493b33543341d43df6db4c92de2473cf49f3 |
action_result.data.\*.Full Details.FileProperties.SSDeep | string | | test 6144:IFkS+8dpN9EtEnROO4T0LbTbHiXuFW0XPBGunX9v62HCTAA1PSahJj3zDbSJ8:CkMy4TGWXuFR5JAxS6Lnbu8 |
action_result.data.\*.Full Details.FileProperties.Sha256 | string | `sha256` | test 0e7fd4dde827a7f0bda82bbfbce4b92a551d0cd296f72e936b8968310d2181cd |
action_result.data.\*.Full Details.Origin.Country | string | | test United States |
action_result.data.\*.Full Details.Origin.Language | string | | test English |
action_result.data.\*.Full Details.Origin.Risk | string | | test LOW |
action_result.data.\*.Full Details.Summary.Category | string | | test EXECS |
action_result.data.\*.Full Details.Summary.Duration | numeric | | 524114 |
action_result.data.\*.Full Details.Summary.FileType | string | | test EXE |
action_result.data.\*.Full Details.Summary.StartTime | numeric | | 1520334357 |
action_result.data.\*.Full Details.Summary.Status | string | | test COMPLETED |
action_result.data.\*.Full Details.SystemSummary.\*.Risk | string | | test LOW |
action_result.data.\*.Full Details.SystemSummary.\*.Signature | string | | test Binary contains paths to development resources |
action_result.data.\*.Full Details.SystemSummary.\*.SignatureSources | string | | test no activity detected |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list url categories'

List all URL categories

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**get_ids_and_names_only** | optional | Whether to retrieve only a list containing URL category IDs and names. Even if displayURL is set to true, URLs will not be returned | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.get_ids_and_names_only | boolean | | |
action_result.data.\*.id | string | `zscaler url category` | test OTHER_RESTRICTED_WEBSITE |
action_result.data.\*.configuredName | string | | test Test-Caution |
action_result.data.\*.description | string | | test OTHER_RESTRICTED_WEBSITE_DESC |
action_result.data.\*.customCategory | boolean | | True False |
action_result.data.\*.editable | boolean | | True False |
action_result.data.\*.customIpRangesCount | numeric | | 0 |
action_result.data.\*.customUrlsCount | numeric | | 0 |
action_result.data.\*.dbCategorizedUrls.\* | string | | test 6.5.3.2.4 |
action_result.data.\*.ipRangesRetainingParentCategoryCount | numeric | | 0 |
action_result.data.\*.scopes.\*.Type | string | | test ORGANIZATION |
action_result.data.\*.type | string | | test URL_CATEGORY |
action_result.data.\*.urlsRetainingParentCategoryCount | numeric | | 0 |
action_result.data.\*.val | numeric | | 1 |
action_result.summary.total_url_categories | numeric | | 10 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'block ip'

Block an IP

Type: **contain** <br>
Read only: **False**

If a <b>url_category</b> is specified, it will add the IP(s) as a rule to that category. If it is left blank, it will instead add the IP(s) to the global blocklist.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | A list of IPs | string | `ip` `ipv6` |
**url_category** | optional | Add to this category | string | `zscaler url category` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ip | string | `ip` `ipv6` | |
action_result.parameter.url_category | string | `zscaler url category` | |
action_result.data.\*.configuredName | string | | test Test-Block |
action_result.data.\*.customCategory | boolean | | True False |
action_result.data.\*.dbCategorizedUrls.\* | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.id | string | | test CUSTOM_01 |
action_result.data.\*.val | numeric | | 128 |
action_result.summary.ignored.\* | string | | test 8.8.8.8 |
action_result.summary.updated.\* | string | | test 208.67.222.222 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'block url'

Block a URL

Type: **contain** <br>
Read only: **False**

If a <b>url_category</b> is specified, it will add the URL(s) as a rule to that category. If it is left blank, it will instead add the URL(s) to the global blocklist.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | A list of URLs | string | `url` `url list` `domain` |
**url_category** | optional | Add to this category | string | `zscaler url category` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.url | string | `url` `url list` `domain` | |
action_result.parameter.url_category | string | `zscaler url category` | |
action_result.data.\*.configuredName | string | | test Test-Block |
action_result.data.\*.customCategory | boolean | | True False |
action_result.data.\*.customUrlsCount | numeric | | 0 |
action_result.data.\*.dbCategorizedUrls.\* | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.editable | boolean | | True False |
action_result.data.\*.id | string | | test CUSTOM_01 |
action_result.data.\*.type | string | | test URL_CATEGORY |
action_result.data.\*.urlsRetainingParentCategoryCount | numeric | | 3 |
action_result.data.\*.val | numeric | | 128 |
action_result.summary.ignored.\* | string | | test www.test.com |
action_result.summary.updated.\* | string | | test www.test123.com |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'unblock ip'

Unblock an IP

Type: **correct** <br>
Read only: **False**

If a <b>url_category</b> is specified, it will remove the IP(s) from that category. If it is left blank, it will instead remove the IP(s) from the global blocklist.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | A list of IPs | string | `ip` `ipv6` |
**url_category** | optional | Remove from this category | string | `zscaler url category` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ip | string | `ip` `ipv6` | |
action_result.parameter.url_category | string | `zscaler url category` | |
action_result.data.\*.configuredName | string | | test Test-Block |
action_result.data.\*.customCategory | boolean | | True False |
action_result.data.\*.dbCategorizedUrls.\* | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.id | string | | test CUSTOM_01 |
action_result.data.\*.val | numeric | | 128 |
action_result.summary.ignored.\* | string | | test 8.8.8.8 |
action_result.summary.updated.\* | string | | test 208.67.222.222 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'unblock url'

Unblock a URL

Type: **correct** <br>
Read only: **False**

If a <b>url_category</b> is specified, it will remove the URL(s) from that category. If it is left blank, it will instead remove the URL(s) from the global blocklist.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | A list of URLs | string | `url` `url list` `domain` |
**url_category** | optional | Remove from this category | string | `zscaler url category` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.url | string | `url` `url list` `domain` | |
action_result.parameter.url_category | string | `zscaler url category` | |
action_result.data.\*.configuredName | string | | test Test-Block |
action_result.data.\*.customCategory | boolean | | True False |
action_result.data.\*.customUrlsCount | numeric | | 0 |
action_result.data.\*.dbCategorizedUrls.\* | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.editable | boolean | | True False |
action_result.data.\*.id | string | | test CUSTOM_01 |
action_result.data.\*.type | string | | test URL_CATEGORY |
action_result.data.\*.urlsRetainingParentCategoryCount | numeric | | 1 |
action_result.data.\*.val | numeric | | 128 |
action_result.summary.ignored.\* | string | | test www.test.com |
action_result.summary.updated.\* | string | | test www.test123.com |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'allow ip'

Add an IP address to the allowlist

Type: **contain** <br>
Read only: **False**

If a <b>url_category</b> is specified, the action adds the IPs to that category. If it is left blank, the action adds the IPs to the global allowlist.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | A list of IPs | string | `ip` `ipv6` |
**url_category** | optional | Add to this category | string | `zscaler url category` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ip | string | `ip` `ipv6` | |
action_result.parameter.url_category | string | `zscaler url category` | |
action_result.data.\*.configuredName | string | | test Test-Allowlist |
action_result.data.\*.customCategory | boolean | | True False |
action_result.data.\*.dbCategorizedUrls.\* | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.id | string | | test CUSTOM_01 |
action_result.data.\*.val | numeric | | 128 |
action_result.data.\*.whitelistUrls.\* | string | | |
action_result.summary.ignored.\* | string | | test 8.8.8.8 |
action_result.summary.updated.\* | string | | test 208.67.222.222 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'allow url'

Add a URL to the allowlist

Type: **contain** <br>
Read only: **False**

If a <b>url_category</b> is specified, the action adds the URLs to that category. If it is left blank, the action adds the URLs to the global allowlist.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | A list of URLs | string | `url` `domain` `url list` |
**url_category** | optional | Add to this category | string | `zscaler url category` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.url | string | `url` `domain` `url list` | |
action_result.parameter.url_category | string | `zscaler url category` | |
action_result.data.\*.configuredName | string | | test Test-Allowlist |
action_result.data.\*.customCategory | boolean | | True False |
action_result.data.\*.customUrlsCount | numeric | | 0 |
action_result.data.\*.dbCategorizedUrls.\* | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.editable | boolean | | True False |
action_result.data.\*.id | string | | test CUSTOM_01 |
action_result.data.\*.type | string | | test URL_CATEGORY |
action_result.data.\*.urlsRetainingParentCategoryCount | numeric | | 3 |
action_result.data.\*.val | numeric | | 128 |
action_result.data.\*.whitelistUrls.\* | string | | |
action_result.summary.ignored.\* | string | | test www.test.com |
action_result.summary.updated.\* | string | | test www.test123.com |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'unallow ip'

Remove an IP address from the allowlist

Type: **correct** <br>
Read only: **False**

If a <b>url_category</b> is specified, it will remove the IP(s) from that category. If it is left blank, it will instead remove the IP(s) from the global allowlist.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | A list of IPs | string | `ip` `ipv6` |
**url_category** | optional | Remove from this category | string | `zscaler url category` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ip | string | `ip` `ipv6` | |
action_result.parameter.url_category | string | `zscaler url category` | |
action_result.data.\*.configuredName | string | | test Test-Allowlist |
action_result.data.\*.customCategory | boolean | | True False |
action_result.data.\*.dbCategorizedUrls.\* | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.id | string | | test CUSTOM_01 |
action_result.data.\*.val | numeric | | 128 |
action_result.data.\*.whitelistUrls.\* | string | | |
action_result.summary.ignored.\* | string | | test 8.8.8.8 |
action_result.summary.updated.\* | string | | test 208.67.222.222 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'unallow url'

Remove a URL from the allowlist

Type: **correct** <br>
Read only: **False**

If a <b>url_category</b> is specified, the action removes the URLs from that category. If it is left blank, the action removes the URLs from the global allowlist.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | A list of URLs | string | `url` `domain` `url list` |
**url_category** | optional | Remove from this category | string | `zscaler url category` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.url | string | `url` `domain` `url list` | |
action_result.parameter.url_category | string | `zscaler url category` | |
action_result.data.\*.configuredName | string | | test Test-Allowlist |
action_result.data.\*.customCategory | boolean | | True False |
action_result.data.\*.dbCategorizedUrls.\* | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.id | string | | test CUSTOM_01 |
action_result.data.\*.val | numeric | | 128 |
action_result.data.\*.whitelistUrls.\* | string | | |
action_result.summary.ignored.\* | string | | test www.test.com |
action_result.summary.updated.\* | string | | test www.test123.com |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup ip'

Look up the categories related to an IP

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | A list of IPs | string | `ip` `ipv6` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ip | string | `ip` `ipv6` | |
action_result.data.\*.url | string | `ip` `ipv6` | test 208.67.222.222 test 8.8.8.8 |
action_result.data.\*.urlClassifications.\* | string | | test WEB_SEARCH |
action_result.data.\*.urlClassificationsWithSecurityAlert.\* | string | | |
action_result.data.\*.blocklisted | boolean | | True False |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup url'

Look up the categories related to a URL

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | A list of URLs | string | `url` `domain` `url list` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.url | string | `url` `domain` `url list` | |
action_result.data.\*.url | string | `url` `domain` `url list` | test www.test.com |
action_result.data.\*.urlClassifications.\* | string | | test MISCELLANEOUS_OR_UNKNOWN |
action_result.data.\*.urlClassificationsWithSecurityAlert.\* | string | | |
action_result.data.\*.blocklisted | boolean | | True False |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'submit file'

Submit a file to Zscaler Sandbox

Type: **generic** <br>
Read only: **False**

This action requires a Sandbox Submission API token. By default, Zscaler antivirus (AV) scans files before submitting them to the sandbox for a verdict. If a verdict already exists, set the 'force' parameter to make the sandbox analyze the file again. You can submit up to 100 files per day.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | required | Vault ID of file to submit | string | `vault id` `sha1` |
**force** | optional | Submit file to sandbox even if found malicious during AV scan and a verdict already exists | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.vault_id | string | `vault id` `sha1` | |
action_result.parameter.force | boolean | | |
action_result.data.\*.code | numeric | | 200 |
action_result.data.\*.fileType | string | | test zip |
action_result.data.\*.md5 | string | `md5` | test 6CE6F415D8475545BE5BA114F208B0FF |
action_result.data.\*.message | string | | test /submit response OK |
action_result.data.\*.sandboxSubmission | string | | test Virus |
action_result.data.\*.virusName | string | | test EICAR_Test_File |
action_result.data.\*.virusType | string | | test Virus |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get admin users'

Get a list of admin users

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** | optional | Maximum number of records to fetch | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.limit | numeric | | |
action_result.data.\*.id | numeric | `zscaler user id` | 889814 |
action_result.data.\*.name | string | | test new_test_long_email_id_new_test_long_email_id_new_test_long_email_id_new_test_long_email |
action_result.data.\*.loginName | string | | test first.last@domain.com |
action_result.data.\*.email | string | `email` | test first.last@emaildomain.com |
action_result.data.\*.role.extensions.adminRank | string | | |
action_result.data.\*.role.extensions.roleType | string | | |
action_result.data.\*.role.id | numeric | | |
action_result.data.\*.role.isNameL10nTag | boolean | | True False |
action_result.data.\*.role.name | string | | test Super Admin |
action_result.data.\*.disabled | boolean | | True False |
action_result.data.\*.adminScopeScopeEntities.\*.id | numeric | | 4460340 |
action_result.data.\*.adminScopeScopeEntities.\*.name | string | | test Example App |
action_result.data.\*.adminScopeType | string | | |
action_result.data.\*.adminScopescopeGroupMemberEntities.\*.id | numeric | | 8035054 |
action_result.data.\*.comments | string | | test This is test user |
action_result.data.\*.isDefaultAdmin | boolean | | True False |
action_result.data.\*.isDeprecatedDefaultAdmin | boolean | | True False |
action_result.data.\*.isExecMobileAppEnabled | boolean | | True False |
action_result.data.\*.isNonEditable | boolean | | True False |
action_result.data.\*.isPasswordLoginAllowed | boolean | | True False |
action_result.data.\*.isProductUpdateCommEnabled | boolean | | True False |
action_result.data.\*.isSecurityReportCommEnabled | boolean | | True False |
action_result.data.\*.isServiceUpdateCommEnabled | boolean | | True False |
action_result.data.\*.pwdLastModifiedTime | numeric | | |
action_result.data.\*.userName | string | | test Last, First |
action_result.summary.total_admin_users | numeric | | 10 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get users'

Get users, optionally filtered by name, department, or group

Type: **investigate** <br>
Read only: **True**

Get users, optionally filtered by name, department, or group. The name parameter performs a partial match. The department and group parameters perform a 'starts with' match.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | optional | User Name/ID | string | |
**department** | optional | User department | string | |
**group** | optional | User group | string | |
**limit** | optional | Maximum number of records to fetch | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.name | string | | |
action_result.parameter.department | string | | |
action_result.parameter.group | string | | |
action_result.parameter.limit | numeric | | |
action_result.data.\*.id | numeric | `zscaler user id` | 889814 |
action_result.data.\*.name | string | | test First Last |
action_result.data.\*.email | string | `email` | test first.last@domain.com |
action_result.data.\*.department.id | numeric | | 81896690 |
action_result.data.\*.department.name | string | | test IT |
action_result.data.\*.disabled | boolean | | True False |
action_result.data.\*.groups.\*.id | numeric | `zscaler group id` | 8894813 |
action_result.data.\*.groups.\*.name | string | | test Super Admin |
action_result.data.\*.adminUser | boolean | | True False |
action_result.data.\*.comments | string | | test This is test user |
action_result.data.\*.deleted | boolean | | True False |
action_result.data.\*.isNonEditable | boolean | | True False |
action_result.summary.total_users | numeric | | 10 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get groups'

Get a list of groups

Type: **investigate** <br>
Read only: **True**

Get groups whose name or comments match the search parameter.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**search** | optional | The search string used to match against a group's name or comments attributes | string | |
**limit** | optional | Maximum number of records to fetch | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.search | string | | |
action_result.parameter.limit | numeric | | |
action_result.data.\*.id | numeric | `zscaler group id` | 8894813 |
action_result.data.\*.name | string | | test Frothly Internet Access |
action_result.data.\*.comments | string | | test This is for testing |
action_result.data.\*.isNonEditable | boolean | | True False |
action_result.summary.total_groups | numeric | | 4 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'add group user'

Add a user to a group

Type: **generic** <br>
Read only: **False**

Add a group to the user's profile.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | Zscaler user ID | numeric | `zscaler user id` |
**group_id** | required | Zscaler group ID | numeric | `zscaler group id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.user_id | numeric | `zscaler user id` | |
action_result.parameter.group_id | numeric | `zscaler group id` | |
action_result.data.\*.adminUser | boolean | | True False |
action_result.data.\*.deleted | boolean | | True False |
action_result.data.\*.department.id | numeric | | 4459551 |
action_result.data.\*.department.name | string | | test Service Admin |
action_result.data.\*.email | string | | test 134@example.us |
action_result.data.\*.groups.\*.id | numeric | | 4460341 |
action_result.data.\*.groups.\*.name | string | | test Example App |
action_result.data.\*.id | numeric | | 9840695 |
action_result.data.\*.name | string | | test Test user |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'remove group user'

Remove a user from a group

Type: **correct** <br>
Read only: **False**

Remove a group from the user's profile.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | Zscaler user ID | numeric | `zscaler user id` |
**group_id** | required | Zscaler group ID | numeric | `zscaler group id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.user_id | numeric | `zscaler user id` | |
action_result.parameter.group_id | numeric | `zscaler group id` | |
action_result.data.\*.adminUser | boolean | | True False |
action_result.data.\*.deleted | boolean | | True False |
action_result.data.\*.department.id | numeric | | 4459551 |
action_result.data.\*.department.name | string | | test Service Admin |
action_result.data.\*.email | string | | test 134@example.us |
action_result.data.\*.groups.\*.id | numeric | | 4459550 |
action_result.data.\*.groups.\*.name | string | | test Service Admin |
action_result.data.\*.id | numeric | | 9840695 |
action_result.data.\*.name | string | | test Elsie |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get allowlist'

Get URLs on the allowlist

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.data.\*.url | string | | |
action_result.summary.total_allowlist_items | numeric | | 10 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get denylist'

Get URLs on the denylist

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter** | optional | Filter results by URL or IP | string | |
**query** | optional | Regular expression to match against each URL or IP | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.filter | string | | |
action_result.parameter.query | string | | |
action_result.data.\*.url | string | | |
action_result.summary.total_denylist_items | numeric | | 10 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update user'

Update the user with the specified ID

Type: **correct** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | Zscaler user ID | numeric | `zscaler user id` |
**user** | optional | JSON object containing the user details (see https://help.zscaler.com/zia/user-management#/users/{userId}-put) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.user_id | numeric | `zscaler user id` | |
action_result.parameter.user | string | | |
action_result.data.\*.adminUser | boolean | | True False |
action_result.data.\*.comments | string | | test This is test user |
action_result.data.\*.deleted | boolean | | True False |
action_result.data.\*.department.id | numeric | | 81896690 |
action_result.data.\*.department.name | string | | test IT |
action_result.data.\*.email | string | `email` | test first.last@domain.com |
action_result.data.\*.groups.\*.id | numeric | `zscaler group id` | 8894813 |
action_result.data.\*.groups.\*.name | string | | test Super Admin |
action_result.data.\*.id | numeric | `zscaler user id` | 889814 |
action_result.data.\*.name | string | | test First Last |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'add category url'

Add URLs to a category

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**category_id** | required | The ID of the category to add the specified URLs to | string | |
**urls** | optional | A comma-separated list of URLs to add to the specified category | string | |
**retaining_parent_category_url** | optional | A comma-separated list of URLs to add to the retaining parent category section inside the specified category | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.category_id | string | | |
action_result.parameter.urls | string | | |
action_result.parameter.retaining_parent_category_url | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.val | numeric | | |
action_result.data.\*.type | string | | |
action_result.data.\*.urls.\* | string | | |
action_result.data.\*.scopes.\*.Type | string | | |
action_result.data.\*.editable | boolean | | True False |
action_result.data.\*.keywords.\* | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.configuredName | string | | |
action_result.data.\*.customCategory | boolean | | True False |
action_result.data.\*.customUrlsCount | numeric | | |
action_result.data.\*.dbCategorizedUrls.\* | string | | |
action_result.data.\*.customIpRangesCount | numeric | | |
action_result.data.\*.keywordsRetainingParentCategory.\* | string | | |
action_result.data.\*.urlsRetainingParentCategoryCount | numeric | | |
action_result.data.\*.ipRangesRetainingParentCategoryCount | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'add category ip'

Add IPs to a category

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**category_id** | required | The ID of the category to add the specified URLs to | string | |
**ips** | optional | A comma-separated list of IP addresses to add to the specified category | string | |
**retaining_parent_category_ip** | optional | A comma-separated list of IPs to add to the retaining parent category section inside the specified category | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.category_id | string | | |
action_result.parameter.ips | string | | |
action_result.parameter.retaining_parent_category_ip | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.val | numeric | | |
action_result.data.\*.type | string | | |
action_result.data.\*.urls.\* | string | | |
action_result.data.\*.scopes.\*.Type | string | | |
action_result.data.\*.editable | boolean | | True False |
action_result.data.\*.keywords.\* | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.configuredName | string | | |
action_result.data.\*.customCategory | boolean | | True False |
action_result.data.\*.customUrlsCount | numeric | | |
action_result.data.\*.dbCategorizedUrls.\* | string | | |
action_result.data.\*.customIpRangesCount | numeric | | |
action_result.data.\*.keywordsRetainingParentCategory.\* | string | | |
action_result.data.\*.urlsRetainingParentCategoryCount | numeric | | |
action_result.data.\*.ipRangesRetainingParentCategoryCount | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'remove category url'

Remove URLs from a category

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**category_id** | required | The ID of the category to add the specified URLs to | string | |
**urls** | optional | A comma-separated list of URLs to remove from the specified category | string | |
**retaining_parent_category_url** | optional | A comma-separated list of URLs to remove from the retaining parent category section inside the specified category | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.category_id | string | | |
action_result.parameter.urls | string | | |
action_result.parameter.retaining_parent_category_url | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.val | numeric | | |
action_result.data.\*.type | string | | |
action_result.data.\*.urls.\* | string | | |
action_result.data.\*.scopes.\*.Type | string | | |
action_result.data.\*.editable | boolean | | True False |
action_result.data.\*.keywords.\* | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.configuredName | string | | |
action_result.data.\*.customCategory | boolean | | True False |
action_result.data.\*.customUrlsCount | numeric | | |
action_result.data.\*.dbCategorizedUrls.\* | string | | |
action_result.data.\*.customIpRangesCount | numeric | | |
action_result.data.\*.keywordsRetainingParentCategory.\* | string | | |
action_result.data.\*.urlsRetainingParentCategoryCount | numeric | | |
action_result.data.\*.ipRangesRetainingParentCategoryCount | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'remove category ip'

Remove IPs from a category

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**category_id** | required | The ID of the category to add the specified URLs to | string | |
**ips** | optional | A comma-separated list of IP addresses to add to the specified category | string | |
**retaining_parent_category_ip** | optional | A comma-separated list of IPs to add to the retaining parent category section inside the specified category | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.category_id | string | | |
action_result.parameter.ips | string | | |
action_result.parameter.retaining_parent_category_ip | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.val | numeric | | |
action_result.data.\*.type | string | | |
action_result.data.\*.urls.\* | string | | |
action_result.data.\*.scopes.\*.Type | string | | |
action_result.data.\*.editable | boolean | | True False |
action_result.data.\*.keywords.\* | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.configuredName | string | | |
action_result.data.\*.customCategory | boolean | | True False |
action_result.data.\*.customUrlsCount | numeric | | |
action_result.data.\*.dbCategorizedUrls.\* | string | | |
action_result.data.\*.customIpRangesCount | numeric | | |
action_result.data.\*.keywordsRetainingParentCategory.\* | string | | |
action_result.data.\*.urlsRetainingParentCategoryCount | numeric | | |
action_result.data.\*.ipRangesRetainingParentCategoryCount | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create destination group'

Create a destination group

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | required | Destination IP group name | string | |
**type** | required | Destination IP group type (i.e., the group can contain destination IP addresses, countries, URL categories or FQDNs) | string | |
**addresses** | optional | Comma-separated destination IP addresses, FQDNs, or wildcard FQDNs to add to the group | string | |
**description** | optional | Additional information about the destination IP group. | string | |
**ip_categories** | optional | Destination IP address URL categories | string | |
**countries** | optional | Destination IP address countries. You can identify destinations based on the location of a server. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.name | string | | |
action_result.parameter.type | string | | |
action_result.parameter.addresses | string | | |
action_result.parameter.description | string | | |
action_result.parameter.ip_categories | string | | |
action_result.parameter.countries | string | | |
action_result.data.\*.id | numeric | | |
action_result.data.\*.name | string | | |
action_result.data.\*.type | string | | DSTN_IP DSTN_FQDN DSTN_DOMAIN DSTN_OTHER |
action_result.data.\*.addresses.\* | string | | 192.168.1.1 |
action_result.data.\*.countries.\* | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.ipCategories.\* | string | | TRADING_BROKARAGE_INSURANCE |
action_result.data.\*.isNonEditable | boolean | | True False |
action_result.data.\*.creatorContext | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list destination group'

List destination groups

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_group_ids** | optional | A comma-separated list of unique identifiers for the IP destination groups | string | |
**exclude_type** | optional | The IP group type to be excluded from the results | string | |
**category_type** | optional | Comma-separated IP group types to include. This parameter is supported only when 'lite' is true | string | |
**limit** | optional | Limit of the results to be retrieved | numeric | |
**lite** | optional | Whether to retrieve only limited information of IP destination groups. Includes ID, name and type of the IP destination groups | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ip_group_ids | string | | |
action_result.parameter.exclude_type | string | | |
action_result.parameter.category_type | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.lite | boolean | | |
action_result.data.\*.id | numeric | | |
action_result.data.\*.name | string | | |
action_result.data.\*.type | string | | DSTN_IP DSTN_FQDN DSTN_DOMAIN DSTN_OTHER |
action_result.data.\*.addresses.\* | string | | 192.168.1.1 |
action_result.data.\*.countries.\* | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.ipCategories.\* | string | | TRADING_BROKARAGE_INSURANCE |
action_result.data.\*.isNonEditable | boolean | | True False |
action_result.data.\*.creatorContext | string | | |
action_result.summary.total_destination_groups | numeric | | 10 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'edit destination group'

Edit a destination group

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_group_id** | required | The unique identifier for the IP destination group | numeric | |
**name** | optional | Destination IP group name | string | |
**addresses** | optional | Comma-separated destination IP addresses, FQDNs, or wildcard FQDNs to assign to the group | string | |
**description** | optional | Additional information about the destination IP group. | string | |
**ip_categories** | optional | Destination IP address URL categories | string | |
**countries** | optional | Destination IP address countries. You can identify destinations based on the location of a server. | string | |
**is_non_editable** | optional | If set to true, the destination IP address group is non-editable. This field is applicable only to predefined IP address groups, which cannot be modified | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ip_group_id | numeric | | |
action_result.parameter.name | string | | |
action_result.parameter.addresses | string | | |
action_result.parameter.description | string | | |
action_result.parameter.ip_categories | string | | |
action_result.parameter.countries | string | | |
action_result.parameter.is_non_editable | boolean | | |
action_result.data.\*.id | numeric | | |
action_result.data.\*.name | string | | |
action_result.data.\*.type | string | | DSTN_IP DSTN_FQDN DSTN_DOMAIN DSTN_OTHER |
action_result.data.\*.addresses.\* | string | | 192.168.1.1 |
action_result.data.\*.countries.\* | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.ipCategories.\* | string | | TRADING_BROKARAGE_INSURANCE |
action_result.data.\*.isNonEditable | boolean | | True False |
action_result.data.\*.creatorContext | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'delete destination group'

Delete destination groups

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_group_ids** | required | A comma-separated list of unique identifiers for the IP destination groups | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ip_group_ids | string | | |
action_result.data.\*.ip_group_id | string | | |
action_result.summary.deleted_destination_groups | numeric | | 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get departments'

Get a list of departments

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | optional | Filter by department name | string | |
**page** | optional | Specifies the page offset | numeric | |
**page_size** | optional | Specifies the page size | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.name | string | | |
action_result.parameter.page | numeric | | |
action_result.parameter.page_size | numeric | | |
action_result.data.\*.id | numeric | | |
action_result.data.\*.name | string | | |
action_result.data.\*.isNonEditable | boolean | | True False |
action_result.summary.total_departments | numeric | | 97 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get category details'

Get the URLs and keywords of a category

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**category_ids** | required | Comma-separated list of category IDs to query | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.category_ids | string | | |
action_result.data.\*.id | string | `zscaler url category` | test OTHER_RESTRICTED_WEBSITE |
action_result.data.\*.configuredName | string | | test Test-Caution |
action_result.data.\*.description | string | | test OTHER_RESTRICTED_WEBSITE_DESC |
action_result.data.\*.customCategory | boolean | | True False |
action_result.data.\*.editable | boolean | | True False |
action_result.data.\*.keywords.\* | string | | |
action_result.data.\*.urls.\* | string | | |
action_result.data.\*.customIpRangesCount | numeric | | 0 |
action_result.data.\*.customUrlsCount | numeric | | 0 |
action_result.data.\*.dbCategorizedUrls.\* | string | | test 6.5.3.2.4 |
action_result.data.\*.keywordsRetainingParentCategory.\* | string | | |
action_result.data.\*.ipRangesRetainingParentCategoryCount | numeric | | 0 |
action_result.data.\*.scopes.\*.Type | string | | test ORGANIZATION |
action_result.data.\*.type | string | | test URL_CATEGORY |
action_result.data.\*.urlsRetainingParentCategoryCount | numeric | | 0 |
action_result.data.\*.val | numeric | | 1 |
action_result.summary.total_categories | numeric | | 97 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
