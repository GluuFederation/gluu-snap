#!/usr/bin/python3
import os
import json
from urllib.request import urlretrieve

cur_dir = os.path.dirname(os.path.realpath(__file__))

app_versions = json.load(open(os.path.join(cur_dir, "app_versions.json")))

def download(url, target_fn):
    dst = os.path.join(cur_dir, "apps", target_fn)
    print("Downloading", url, "to", dst)
    urlretrieve(url, dst)

download('https://d3pxv6yz143wms.cloudfront.net/{0}/amazon-corretto-{0}-linux-x64.tar.gz'.format(app_versions['AMAZON_CORRETTO_VERSION']), 'amazon-corretto.tar.gz')
download('https://repo1.maven.org/maven2/org/eclipse/jetty/jetty-distribution/{0}/jetty-distribution-{0}.tar.gz'.format(app_versions['JETTY_VERSION']), 'jetty.tar.gz')
download('https://repo1.maven.org/maven2/org/python/jython-installer/{0}/jython-installer-{0}.jar'.format(app_versions['JYTHON_VERSION']), 'jython-installer.jar')
download('https://ox.gluu.org/maven/org/gluu/oxauth-server/{0}{1}/oxauth-server-{0}{1}.war'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), 'oxauth-server.war')

