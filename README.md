# Netnea OWASP CRS Upgrading Plugin

## Description

The CRS Upgrading Plugin simplifies the upgrade process from CRS v3 to CRS v4. The upgrade process is divided into multiple steps. The plugin supports the following features:

Step 1: Run CRS v3 and CRS v4 **in parallel**, CRS v3 in blocking mode (or whatever was previously configured) and **CRS v4 in log-only mode**.

Step 2: Start **CRS v4 in blocking mode** for some of the requests:

Step 2a: Run CRS v4 for **specific paths** and continue running CRS v3 for specific paths.

Step 2b: For the remaining requests (those not configured for CRS v3 or CRS v4), you can specify the percentage of requests for which CRS v4 should be applied (**sampling mode**).

![CRS Upgrading Process](netnea-crs-upgrading-plugin.png)

Once either all parts of the application (all paths) are configured for CRS v4 or no paths are configured for CRS v3 AND the sampling mode percentage is set to 100, the upgrade plugin can be removed. The following steps are required:
1. Remove CRS v3 folder and includes in your configuration.
2. Change rule ids in CRS v4 from 8'9xx'xxx to 9xx'xxx again.
3. First disable, then delete netnea-crs-upgrading-plugin 

## Prerequisites

* Download, untar and install the latest OWASP CRS v4
* Change the rule ids of CRS v4 from range 9xx'xxx to 8'9xx'xxx

`sed -i '' 's/id:\(9.....\)/id:8\1/' /opt/apache/conf/crs4/rules/RE*.conf`

* Change the name of the variables `tx.outbound_anomaly_score_plx`

`sed -i '' 's/\(tx.outbound_anomaly_score_pl.\)/\1_crs4/g' /opt/apache/conf/crs4/rules/RES*.conf`

### crs-setup.conf

The crs-setup.conf slightly changed between CRS v3 and v4. If you set one or more of the following rules or variables, please change to the new format.

#### Paranoia Level higher than 1

If you set the paranoia level in rule 900000 with the variable `tx.paranoia_level`, you also have to set the new variable in CRS v4, `tx.blocking_paranoia_level` like for example:

```
SecAction "id:900000,phase:1,pass,nolog,\ 
  setvar:tx.paranoia_level=2,\            
  setvar:tx.blocking_paranoia_level=2"
```

During the upgrading process, you have to set both variables.

#### Executing Paranoia Level

If you set the variable `tx.executing_paranoia_level` you also have to set the new variable in CRS v4, `tx.detection_paranoia_level`.

#### Application specific exclusions

In CRS 4, application specific exclusions are no longer part of the CRS itself, but they are available as "CRS plugins". If you set one ore more application specific exclusions in rule 900130, you have to install the corresponding plugin.

Plugins are not installed by default, but can be downloaded from the plugin registry: https://github.com/coreruleset/plugin-registry.

For detailed information about using and installing plugins, please see https://coreruleset.org/docs/concepts/plugins/.

#### Allowed Request Content Type

If you set custom request content types in rule 900280 via the variable `tx.allowed_request_content_type_charset`, please change the configuration from `tx.allowed_request_content_type_charset=utf-8|iso-8859-1|...` to `tx.allowed_request_content_type_charset=|utf-8| |iso-8859-1| ...`

#### DoS Protection

If you used DoS protection, please install and use the corresponding plugin https://github.com/coreruleset/dos-protection-plugin-modsecurity.

## Plugin Installation

For full and up to date instructions for the different available plugin installation methods, refer to [How to Install a Plugin](https://coreruleset.org/docs/concepts/plugins/#how-to-install-a-plugin) in the official CRS documentation.

CRS has had a plugin structure since version 4. This means that for CRS version 3, we need to add the plugin folder (`conf/crs4/plugins/`) and the include directives for the plugin itself to apache.conf:

```
# === ModSec Core Rule Set Base Configuration (ids: 900000-900999)

Include    /opt/apache/conf/crs3/crs-setup.conf  <--- crs4/setup.conf (FIXME: check!!)

# === Plugin

Include conf/crs4/plugins/*-config.conf          <---
Include conf/crs4/plugins/*-before.conf          <---


SecAction "id:900110,phase:1,pass,nolog,\
  setvar:tx.inbound_anomaly_score_threshold=5,\
  setvar:tx.outbound_anomaly_score_threshold=4"

#CRS3 variable name: tx.paranoia_level
#CRS4 variable name: tx.blocking_paranoia_level
SecAction "id:900000,phase:1,pass,nolog,\
  setvar:tx.paranoia_level=2,\
  setvar:tx.blocking_paranoia_level=2"          <--- 
...

# === ModSecurity Core Rule Set Inclusion

Include    /opt/apache/conf/crs4/rules/*.conf   <--- has to be before crs3
Include    /opt/apache/conf/crs3/rules/*.conf

# === Plugin

Include conf/crs4/plugins/*-after.conf          <---
```

## Configuration

### netnea-crs-upgrading-config.conf

As in any other plugin, the netnea-crs-upgrading-plugin can be disabled by deleting the comment of this rule:
```
SecRule &TX:netnea-crs-upgrading-plugin_enabled "@eq 0" \
  "id:9525010,\
  phase:1,\
  pass,\
  nolog,\
  setvar:'tx.netnea-crs-upgrading-plugin_enabled=0'"
```

Step 1: Parallel Mode:  
The following rule 9525100 removes the inbound and outbound blocking rules of CRS v4 so that all CRS v4 rules are executed but the blocking rules are not. This allows us to run CRS v4 rules in logonly mode and CRS v3 in blocking mode (step 1 of the process as decribed above).  
Comment out this rule if you want to exit parallel mode and block some of the requests (the configuration is explained later).
```
# Rule 9525100 enables the parallel mode of CRS3 and CRS4
# by removing the blocking rules of CRS4.
# It's step 1 of the upgrading process as described in the README.
#
SecAction \
  "id:9525100,\
   phase:1,\
   pass,\
   nolog,\
   noauditlog,\
   setvar:'tx.reporting_upgrading=upgrading-plugin running in parallel mode',\
   tag:'netnea-crs-upgrading-plugin',\
   ver:'netnea-crs-upgrading-plugin/1.0.0',\
   ctl:ruleRemoveById=8949110,ctl:ruleRemoveById=8959100,\
   ctl:ruleRemoveById=9525101-9525799"
```

Step 2b: Sampling Mode:  
The following rule 9525200 specifies the percentage of requests that should run through CRS v4. The rest should run through CRS v3 (step 2b of the process as described above).
```
# Step 2 of upgrading process:
# Rule 9525100 sets the percentage of requests that should run through CRS4
# A value 0, for example, means that all requests run through CRS3.
# A value of 100 means, all requests run through CRS4.
#
SecAction \
  "id:9525200,\
   phase:1,\
   pass,\
   nolog,\
   noauditlog,\
   tag:'netnea-crs-upgrading-plugin',\
   ver:'netnea-crs-upgrading-plugin/1.0.0',\
   setvar:tx.sampling_percentage_netnea-crs-upgrading=10"
```

### paths_crs3.data and paths_crs4.data

The paths for CRS v3 and CRS v4 can be configured in the two data files paths_crs3.data and paths_crs4.data.

Example paths_crs4.data:
```
# Paths that can already run through CRS v4
/crs4
/another_crs4_path
```

### Reporting in netnea-crs-upgrading-after.conf

To avoid unnecessary log entries, the netnea-crs-upgrading-plugin rules are set to nolog. A single reporting log entry per request can be created by commenting out the following reporting rule in netnea-crs-upgrading-after.conf.

```
# Rule 9525800 can be uncommented if logging of the netnea-crs-upgrading-plugin is needed
SecAction \
    "id:9525800,\
    phase:5,\
    pass,\
    t:none,\
    noauditlog,\
    msg:'Reporting upgrading-plugin: %{tx.reporting_upgrading}',\
    tag:'reporting',\
    tag:'netnea-crs-upgrading-plugin',\
    ver:'netnea-crs-upgrading-plugin/1.0.0'"
```

## Testing

A testing protocol is available but not published yet.

## Known Problems

None so far

