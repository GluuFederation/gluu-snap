#!/usr/bin/python3
import os
import json
from urllib.request import urlretrieve

cur_dir = os.path.dirname(os.path.realpath(__file__))
app_dir = os.path.join(cur_dir, 'apps')
app_versions = json.load(open(os.path.join(cur_dir, "setup/app_versions.json")))

if not os.path.exists(app_dir):
    os.mkdir(app_dir)

def download(url, target_fn):
    dst = os.path.join(app_dir, target_fn)
    print("Downloading", url, "to", dst)
    urlretrieve(url, dst)

download('https://d3pxv6yz143wms.cloudfront.net/{0}/amazon-corretto-{0}-linux-x64.tar.gz'.format(app_versions['AMAZON_CORRETTO_VERSION']), 'amazon-corretto.tar.gz')
download('https://repo1.maven.org/maven2/org/eclipse/jetty/jetty-distribution/{0}/jetty-distribution-{0}.tar.gz'.format(app_versions['JETTY_VERSION']), 'jetty.tar.gz')
download('https://repo1.maven.org/maven2/org/python/jython-installer/{0}/jython-installer-{0}.jar'.format(app_versions['JYTHON_VERSION']), 'jython-installer.jar')
download('https://ox.gluu.org/maven/org/gluu/oxauth-server/{0}{1}/oxauth-server-{0}{1}.war'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), 'oxauth-server.war')
download('https://ox.gluu.org/maven/org/gluu/oxtrust-server/{0}{1}/oxtrust-server-{0}{1}.war'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), 'oxtrust-server.war')
download('https://ox.gluu.org/maven/org/forgerock/opendj/opendj-server-legacy/{0}/opendj-server-legacy-{0}.zip'.format(app_versions['OPENDJ_VERSION']), 'opendj-server.zip')
download('https://github.com/GluuFederation/community-edition-setup/archive/{}.zip'.format(app_versions['SETUP_BRANCH']), 'community-edition-setup.zip')
download('https://ox.gluu.org/maven/org/gluu/oxauth-client/{0}{1}/oxauth-client-{0}{1}-jar-with-dependencies.jar'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), 'oxauth-client-jar-with-dependencies.jar')
