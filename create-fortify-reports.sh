#!/usr/bin/env bash

#
# Copyright 2013-2016 Guardtime, Inc.
#
# This file is part of the Guardtime client SDK.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
# "Guardtime" and "KSI" are trademarks or registered trademarks of
# Guardtime, Inc., and no license to trademarks is granted; Guardtime
# reserves and retains all trademark rights.
#

rm -rf fortify-reports
mkdir fortify-reports

mvn clean package install
mvn sca:translate
mvn sca:scan

ReportGenerator -format PDF -f fortify-reports/ksi-api-fortify-report.pdf -source $(ls ksi-api/target/*.fpr)
ReportGenerator -format PDF -f fortify-reports/ksi-common-fortify-report.pdf -source $(ls ksi-common/target/*.fpr)
ReportGenerator -format PDF -f fortify-reports/ksi-service-client-fortify-report.pdf -source $(ls ksi-service-client/target/*.fpr)
ReportGenerator -format PDF -f fortify-reports/ksi-service-client-apache-http-fortify-report.pdf -source $(ls ksi-service-client-apache-http/target/*.fpr)
ReportGenerator -format PDF -f fortify-reports/ksi-service-client-simple-http-fortify-report.pdf -source $(ls ksi-service-client-simple-http/target/*.fpr)
ReportGenerator -format PDF -f fortify-reports/ksi-service-client-common-http-fortify-report.pdf -source $(ls ksi-service-client-common-http/target/*.fpr)
ReportGenerator -format PDF -f fortify-reports/ksi-service-client-tcp-fortify-report.pdf -source $(ls ksi-service-client-tcp/target/*.fpr)