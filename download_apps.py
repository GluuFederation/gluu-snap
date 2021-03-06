#!/usr/bin/python3
import os
import sys
import json
import zipfile

from urllib.request import urlretrieve

cur_dir = os.path.dirname(os.path.realpath(__file__))
app_dir = os.path.join(cur_dir, 'apps')
app_versions = json.load(open(os.path.join(cur_dir, "setup/app_versions.json")))

def download(url, target_fn):
    dst = os.path.join(app_dir, target_fn)
    pardir, fn = os.path.split(dst)
    if not os.path.exists(pardir):
        os.makedirs(pardir) 
    print("Downloading", url, "to", dst)
    urlretrieve(url, dst)

if not '-e' in sys.argv:
    download('https://d3pxv6yz143wms.cloudfront.net/{0}/amazon-corretto-{0}-linux-x64.tar.gz'.format(app_versions['AMAZON_CORRETTO_VERSION']), 'corretto/amazon-corretto.tar.gz')
    download('https://repo1.maven.org/maven2/org/eclipse/jetty/jetty-distribution/{0}/jetty-distribution-{0}.tar.gz'.format(app_versions['JETTY_VERSION']), 'jetty/jetty.tar.gz')
    download('https://repo1.maven.org/maven2/org/python/jython-installer/{0}/jython-installer-{0}.jar'.format(app_versions['JYTHON_VERSION']), 'jython/jython-installer.jar')
    download('https://ox.gluu.org/maven/org/gluu/oxauth-server/{0}{1}/oxauth-server-{0}{1}.war'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), 'oxauth/oxauth.war')
    download('https://ox.gluu.org/maven/org/gluu/oxtrust-server/{0}{1}/oxtrust-server-{0}{1}.war'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), 'identity/identity.war')
    download('https://ox.gluu.org/maven/org/forgerock/opendj/opendj-server-legacy/{0}/opendj-server-legacy-{0}.zip'.format(app_versions['OPENDJ_VERSION']), 'opendj/opendj-server.zip')
    download('https://github.com/GluuFederation/community-edition-setup/archive/{}.zip'.format(app_versions['SETUP_BRANCH']), 'setup/community-edition-setup.zip')
    download('https://ox.gluu.org/maven/org/gluu/oxauth-client/{0}{1}/oxauth-client-{0}{1}-jar-with-dependencies.jar'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), 'oxauth/oxauth-client-jar-with-dependencies.jar')
    download('https://ox.gluu.org/maven/org/gluu/oxShibbolethStatic/{0}{1}/oxShibbolethStatic-{0}{1}.jar'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), 'idp/shibboleth-idp.jar')
    download('https://ox.gluu.org/maven/org/gluu/oxshibbolethIdp/{0}{1}/oxshibbolethIdp-{0}{1}.war'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), 'idp/idp.war')
    download('https://ox.gluu.org/npm/passport/passport-{}.tgz'.format(app_versions['OX_VERSION']), 'passport/passport.tgz')
    download('https://ox.gluu.org/npm/passport/passport-version_{}-node_modules.tar.gz'.format(app_versions['PASSPORT_NODE_VERSON']), 'passport/passport-node_modules.tar.gz')
    download('https://nodejs.org/dist/{0}/node-{0}-linux-x64.tar.xz'.format(app_versions['NODE_VERSION']), 'node/node.tar.xz')
    download('https://ox.gluu.org/maven/org/gluu/super-gluu-radius-server/{0}{1}/super-gluu-radius-server-{0}{1}.jar'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), 'radius/super-gluu-radius-server.jar')
    download('https://ox.gluu.org/maven/org/gluu/super-gluu-radius-server/{0}{1}/super-gluu-radius-server-{0}{1}-distribution.zip'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), 'radius/gluu-radius-libs.zip')
    download('https://ox.gluu.org/maven/org/gluu/oxd-server/{0}{1}/oxd-server-{0}{1}-distribution.zip'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), 'oxd-server/oxd-server.zip')


download('https://ox.gluu.org/maven/org/gluu/casa/{0}{1}/casa-{0}{1}.war'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), 'casa/casa.war')
download('https://repo1.maven.org/maven2/com/twilio/sdk/twilio/{0}/twilio-{0}.jar'.format(app_versions['TWILIO_VERSION']), 'casa/twilio-{0}.jar'.format(app_versions['TWILIO_VERSION']))
download('https://repo1.maven.org/maven2/org/jsmpp/jsmpp/{0}/jsmpp-{0}.jar'.format(app_versions['JSMPP_VERSION']), 'casa/jsmpp-{0}.jar'.format(app_versions['JSMPP_VERSION']))
download('https://github.com/GluuFederation/casa/raw/version_{}/extras/casa.pub'.format(app_versions['OX_VERSION']), 'casa/casa.pub')




# we need some files form community-edition-setup.zip
ces = os.path.join( app_dir, 'setup/community-edition-setup.zip')
ces_zip = zipfile.ZipFile(ces)
ces_par_dir = ces_zip.namelist()[0]

def extract_from_ces(src, target_fn):
    dst = os.path.join(app_dir, target_fn)
    print("Extracting {} from community-edition-setup.zip to {}".format(src, dst))
    content = ces_zip.read(os.path.join(ces_par_dir, src))
    p, f = os.path.split(dst)

    if not os.path.exists(p):
        os.makedirs(p)

    with open(dst, 'wb') as w:
        w.write(content)

extract_from_ces('static/system/initd/passport', 'passport/passport')
extract_from_ces('static/radius/etc/init.d/gluu-radius', 'radius/gluu-radius')
extract_from_ces('static/oxd-server/oxd-server.init', 'oxd-server/start/oxd-server')
