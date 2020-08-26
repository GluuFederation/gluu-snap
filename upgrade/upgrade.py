#!/usr/bin/env python3

import os
import sys
import code
import time
import ldap3
import json
import glob
import re

#TODO: check if upgrade is needed

result = input("Starting upgrade. CONTINUE? (y|N): ")
if not result.strip() or (result.strip() and result.strip().lower()[0] != 'y'):
    print("You can re-run this script to upgrade. Bye now ...")
    sys.exit()

snap_common_dir = os.environ['SNAP_COMMON']
snap_dir = os.environ['SNAP']
ces_dir = os.path.join(snap_common_dir, 'install/community-edition-setup')
open(os.path.join(ces_dir, '__init__.py'),'w').close()
sys.path.append(ces_dir)

from setup_app import paths
paths.LOG_FILE = os.path.join(ces_dir, 'logs/upgrade421.log')
paths.LOG_ERROR_FILE = os.path.join(ces_dir, 'logsupgrade421_error.log')
paths.LOG_OS_CHANGES_FILE = os.path.join(ces_dir, 'logsupgrade421_os-changes.log')

print("Starting WrenDS")
os.system('snapctl restart {}.opendj'.format(os.environ['SNAP_NAME']))

from setup_app import static
from setup_app.utils import base
from setup_app.config import Config
from setup_app.utils.db_utils import dbUtils
from setup_app.utils import ldif_utils
from setup_app.utils.setup_utils import SetupUtils
from setup_app.utils.collect_properties import CollectProperties
from setup_app.installers.base import BaseInstaller
from setup_app.installers.gluu import GluuInstaller
from setup_app.installers.httpd import HttpdInstaller
from setup_app.installers.jetty import JettyInstaller
from setup_app.installers.node import NodeInstaller
from setup_app.installers.saml import SamlInstaller
from setup_app.installers.passport import PassportInstaller

Config.init(paths.INSTALL_DIR)
Config.determine_version()

SetupUtils.init()

collectProperties = CollectProperties()
collectProperties.collect()

httpdinstaller = HttpdInstaller()
gluuInstaller = GluuInstaller()
gluuInstaller.initialize()
gluuInstaller.encode_passwords()

jettyInstaller = JettyInstaller()
jettyInstaller.calculate_selected_aplications_memory()
Config.templateRenderingDict['jetty_dist'] = Config.jetty_base

samlInstaller = SamlInstaller()
passportInstaller = PassportInstaller()

jetty_temp = os.path.join(snap_common_dir, 'gluu/jetty/temp')
if not os.path.exists(jetty_temp):
    os.makedirs(jetty_temp, exist_ok=True)

def flatten(k):
    return k.lower().replace('`','').replace(' ', '').replace('(','').replace(')','')

def make_key(l):
    return [ flatten('{}'.format(k)) for k in l ]


class GluuUpdater(BaseInstaller, SetupUtils):
    def __init__(self):
        self.up_version = Config.currentGluuVersion = '4.2.1'

        self.build_tag = '-SNAPSHOT'
        self.backup_time = time.strftime('%Y-%m-%d.%H:%M:%S')

        self.delete_from_configuration = ['gluuFreeDiskSpace', 'gluuFreeMemory', 'gluuFreeSwap', 'gluuGroupCount', 'gluuIpAddress', 'gluuPersonCount', 'gluuSystemUptime']

        self.casa_plugins = {
            'strong-authn-settings': 'https://ox.gluu.org/maven/org/gluu/casa/plugins/strong-authn-settings/{0}{1}/strong-authn-settings-{0}{1}-jar-with-dependencies.jar',
            'account-linking': 'https://ox.gluu.org/maven/org/gluu/casa/plugins/account-linking/{0}{1}/account-linking-{0}{1}-jar-with-dependencies.jar',
            'authorized-clients': 'https://ox.gluu.org/maven/org/gluu/casa/plugins/authorized-clients/{0}{1}/authorized-clients-{0}{1}-jar-with-dependencies.jar',
            'custom-branding': 'https://ox.gluu.org/maven/org/gluu/casa/plugins/custom-branding/{0}{1}/custom-branding-{0}{1}-jar-with-dependencies.jar',
            }

    def prepare_persist_changes(self):
        self.persist_changes = { 
                    ('oxAuthConfDynamic', 'ou=oxauth,ou=configuration,o=gluu'): [
                        ('backchannelAuthenticationEndpoint', 'add', 'entry', 'https://{}/oxauth/restv1/bc-authorize'.format(Config.hostname)),
                        ('backchannelDeviceRegistrationEndpoint', 'add', 'entry', 'https://{}/oxauth/restv1/bc-deviceRegistration'.format(Config.hostname)),
                        ('deviceAuthzEndpoint', 'add', 'entry', 'https://{}/oxauth/restv1/device_authorization'.format(Config.hostname)),
                        ('uiLocalesSupported', 'change', 'entry', ['en', 'bg', 'de', 'es', 'fr', 'it', 'ru', 'tr']),
                        ('clientRegDefaultToCodeFlowWithRefresh', 'add', 'entry', True),
                        ('changeSessionIdOnAuthentication', 'add', 'entry', True),
                        ('returnClientSecretOnRead', 'add', 'entry', True),
                        ('fido2Configuration', 'remove', 'entry', None),
                        ('loggingLevel', 'add', 'entry', 'INFO'),
                        ('loggingLayout', 'add', 'entry', 'text'),
                        ('errorHandlingMethod', 'add', 'entry', 'internal'),
                        ('useLocalCache', 'add', 'entry', True),
                        ('backchannelTokenDeliveryModesSupported', 'add', 'entry', []),
                        ('backchannelAuthenticationRequestSigningAlgValuesSupported', 'add', 'entry', []),
                        ('backchannelClientId', 'add', 'entry', ''),
                        ('backchannelRedirectUri', 'add', 'entry', ''),
                        ('backchannelUserCodeParameterSupported', 'add', 'entry', False),
                        ('backchannelBindingMessagePattern', 'add', 'entry', '^[a-zA-Z0-9]{4,8}$'),
                        ('backchannelAuthenticationResponseExpiresIn', 'add', 'entry',  3600),
                        ('backchannelAuthenticationResponseInterval', 'add', 'entry', 2),
                        ('backchannelRequestsProcessorJobIntervalSec', 'add', 'entry', 0),
                        ('backchannelRequestsProcessorJobChunkSize', 'add', 'entry', 100),
                        ('cibaGrantLifeExtraTimeSec', 'add', 'entry', 180),
                        ('cibaMaxExpirationTimeAllowedSec', 'add', 'entry',  1800),
                        ('backchannelLoginHintClaims', 'add', 'entry', ['inum', 'uid', 'mail']),
                        ('cibaEndUserNotificationConfig', 'add', 'entry', {'databaseURL': '', 'notificationKey': '', 'appId': '', 'storageBucket': '', 'notificationUrl': '', 'messagingSenderId': '', 'publicVapidKey': '', 'projectId': '', 'authDomain': '', 'apiKey': ''}),
                        ('deviceAuthorizationEndpoint', 'add', 'entry', 'https://{}/oxauth/restv1/device-authorization'.format(Config.hostname)),
                        ('grantTypesSupported', 'add', 'element', 'urn:ietf:params:oauth:grant-type:device_code'),
                        ('dynamicGrantTypeDefault', 'add', 'element', 'urn:ietf:params:oauth:grant-type:device_code'),
                        ('deviceAuthzRequestExpiresIn', 'add', 'entry', 1800),
                        ('deviceAuthzTokenPollInterval', 'add', 'entry', 5),
                        ('deviceAuthzResponseTypeToProcessAuthz', 'add', 'entry', 'code'),
                    ],
    
                    ('oxAuthConfStatic', 'ou=oxauth,ou=configuration,o=gluu'): [
                        ('baseDn', 'change', 'subentry', ('sessions', 'ou=sessions,o=gluu')),
                        ('baseDn', 'change', 'subentry', ('ciba', 'ou=ciba,o=gluu')),
                    ],
    
                    ('oxTrustConfApplication', 'ou=oxtrust,ou=configuration,o=gluu'): [
                        ('loggingLayout', 'add', 'entry', 'text'),
                    ],
                    
                    ('oxConfApplication', 'ou=oxidp,ou=configuration,o=gluu'): [
                            ('scriptDn', 'add', 'entry', 'ou=scripts,o=gluu'),
                    ],
                    
                    ('oxTrustConfCacheRefresh', 'ou=oxtrust,ou=configuration,o=gluu'): [
                        ('inumConfig', 'change', 'subentry', ('bindDN', Config.ldap_binddn)),
                    ]

                }


    def fix_gluu_config(self):
        print("Fixing Gluu configuration files")
        with open(Config.gluu_properties_fn) as f:
            gluu_prop = f.readlines()

        for l in gluu_prop:
            if l.startswith('fido2_ConfigurationEntryDN'):
                break
        else:
            for i, l in enumerate(gluu_prop[:]):
                if l.strip().startswith('oxradius_ConfigurationEntryDN'):
                    gluu_prop.insert(i+1, 'fido2_ConfigurationEntryDN=ou=fido2,ou=configuration,o=gluu\n')
                    break

            self.writeFile(Config.gluu_properties_fn, ''.join(gluu_prop))


        idp_default_fn = '/etc/default/idp'

        if os.path.exists(idp_default_fn):
            with open(idp_default_fn) as f:
                idp_default = f.readlines()

            for i, l in enumerate(idp_default[:]):
                ls = l.strip()
                if ls.startswith('JAVA_OPTIONS') and not '-Dpython.home' in ls:
                    n = ls.find('=')
                    options = ls[n+1:].strip()
                    if options.startswith('"') and options.endswith('"'):
                        options = options.strip('"').strip()
                    elif options.startswith("'") and options.endswith("'"):
                        options = options.strip("'").strip()

                    options += ' -Dpython.home=' + Config.jython_home
                    idp_default[i] = 'JAVA_OPTIONS="{}"\n'.format(options)
                    self.writeFile(idp_default_fn, ''.join(idp_default))

        passport_default_fn = '/etc/default/passport'
        if os.path.exists(passport_default_fn):
            Config.node_base = NodeInstaller.node_base
            passport_default = self.render_template(os.path.join(ces_dir, 'templates/node/passport'))
            self.writeFile(passport_default_fn, passport_default)

    def apply_persist_changes(self, js_conf, data):
        for key, change_type, how_change, value in data:
            if change_type == 'add':
                if how_change == 'entry':
                    js_conf[key] = value
                elif how_change == 'element':
                    if not value in js_conf[key]:
                        js_conf[key].append(value)
            elif change_type == 'change':
                if how_change == 'entry':
                    js_conf[key] = value
                if how_change == 'subentry':
                    js_conf[key][value[0]] = value[1]
            elif change_type == 'remove':
                if how_change == 'entry':
                    if key in js_conf:
                        del js_conf[key]
                elif how_change == 'element':
                    if value in js_conf[key]:
                        js_conf[key].remove(value)


    def update_ldap(self):


        dn = 'ou=sessions,o=gluu'
        dbUtils.ldap_conn.search(
                    search_base=dn, 
                    search_scope=ldap3.BASE, 
                    search_filter='(objectClass=*)', 
                    attributes=['*']
                    )
        if not dbUtils.ldap_conn.response:
            print("Adding sessions base entry")
            dbUtils.ldap_conn.add(dn, attributes={'objectClass': ['top', 'organizationalUnit'], 'ou': ['sessions']})


        dn = 'ou=configuration,o=gluu'

        for config_element, config_dn in self.persist_changes:
            print("Updating", config_element)
            ldap_filter = '({0}=*)'.format(config_element)

            dbUtils.ldap_conn.search(
                        search_base=config_dn, 
                        search_scope=ldap3.BASE, 
                        search_filter=ldap_filter, 
                        attributes=[config_element]
                    )
            result = dbUtils.ldap_conn.response
            sdn = result[0]['dn']
            js_conf = json.loads(result[0]['attributes'][config_element][0])
            self.apply_persist_changes(js_conf, self.persist_changes[(config_element, config_dn)])
            new_conf = json.dumps(js_conf,indent=4)

            dbUtils.ldap_conn.modify(
                            sdn, 
                            {config_element: [ldap3.MODIFY_REPLACE, new_conf]}
                            )

        dbUtils.ldap_conn.search(
                    search_base=dn, 
                    search_scope=ldap3.BASE,
                    search_filter='(objectclass=*)',
                    attributes=self.delete_from_configuration
                    )
        
        result = dbUtils.ldap_conn.response
        
        remove_list = []
        
        for k in result[0]['attributes']:
            if result[0]['attributes'][k]:
                    dbUtils.ldap_conn.modify(
                    dn, 
                    {k: [ldap3.MODIFY_DELETE, result[0]['attributes'][k]]}
                    )

        # we need to delete index oxAuthExpiration before restarting opendj
        oxAuthExpiration_index_dn = 'ds-cfg-attribute=oxAuthExpiration,cn=Index,ds-cfg-backend-id=userRoot,cn=Backends,cn=config'
        dbUtils.ldap_conn.search(
            search_base=oxAuthExpiration_index_dn, 
            search_scope=ldap3.BASE, 
            search_filter='(objectclass=*)', 
            attributes=['ds-cfg-attribute']
            )

        if dbUtils.ldap_conn.response:        
            dbUtils.ldap_conn.delete(oxAuthExpiration_index_dn)

        dbUtils.ldap_conn.unbind()

        # update opendj schema and restart
        self.run(['cp', '-f', 
                            os.path.join(ces_dir, 'static/opendj/101-ox.ldif'),
                            os.path.join(Config.ldapBaseFolder, 'config/schema')
                            ])

        print("Restarting WrenDS ...")
        self.restart('opendj')
        dbUtils.ldap_conn.bind()

    def update_war_files(self):
        print("Updating war files")
        for service in jettyInstaller.jetty_app_configuration:
            service_webapps_dir = os.path.join(Config.jetty_base, service, 'webapps')
            if os.path.exists(service_webapps_dir):
                war_file = os.path.join(Config.distGluuFolder, service+'.war')
                print("Copying", war_file, "to", service_webapps_dir)
                self.run(['cp', '-f',  war_file, service_webapps_dir])
                print("Restarting", service)
                self.restart(service)


    def update_scripts(self):
        print("Updating Scripts")

        #TODO: add scripts 
        #if os.path.exists(os.path.join(Config.gluuOptFolder, 'node/passport')):
        #    Config.enable_scim_access_policy = 'true'

        self.prepare_base64_extension_scripts()
        ldif_scripts = os.path.join(Config.outputFolder, 'scripts.ldif')
        self.renderTemplate(ldif_scripts)
        self.logIt("Parsing", ldif_scripts)
        print("Parsing", ldif_scripts)
        parser = ldif_utils.myLdifParser(ldif_scripts)
        parser.parse()

        #TODO: do later
        #if os.path.exists(self.casa_base_dir):
        #    self.setupObj.renderTemplate(self.setupObj.ldif_scripts_casa)
        #    ldif_casa_scripts_fn = os.path.join(self.setupObj.outputFolder, os.path.basename(self.setupObj.ldif_scripts_casa))
        #    self.setupObj.logIt("Parsing", ldif_casa_scripts_fn)
        #    print("Parsing", ldif_casa_scripts_fn)
        #    casa_scripts_parser = self.myLdifParser(ldif_casa_scripts_fn)
        #    casa_scripts_parser.parse()
        #    for e in casa_scripts_parser.entries:
        #        print("Adding casa script", e[0])
        #        self.parser.entries.append(e)

        for dn, entry in parser.entries:
            print("Updating script", dn)
            try:
                dbUtils.ldap_conn.modify(
                    dn, 
                    {'oxScript': [ldap3.MODIFY_REPLACE, entry['oxScript'][0]]}
                    )
            except Exception as e:
                dbUtils.ldap_conn.add(dn, attributes=entry)

    def render_template(self, tmp_file):
        format_dict = self.merge_dicts(Config.__dict__, Config.templateRenderingDict)
        temp = self.readFile(tmp_file)
        temp = self.fomatWithDict(temp,  format_dict)
        
        return temp

    def update_shib(self):

        saml_meta_data_fn = '/opt/shibboleth-idp/metadata/idp-metadata.xml'

        if not os.path.exists(saml_meta_data_fn):
            return

        print("Updadting shibboleth-idp")

        print("Backing up ...")
        idp_dir = os.path.join(snap_common_dir, 'gluu/shibboleth-idp')
        backup_dir = idp_dir + '-back.' + os.urandom(3).hex() + '~'
        
        self.run(['mv', idp_dir, backup_dir ])
        self.createDirs(idp_dir)
        
        print("Updating idp-metadata.xml")
        Config.templateRenderingDict['idp3SigningCertificateText'] = open('/etc/certs/idp-signing.crt').read().replace('-----BEGIN CERTIFICATE-----','').replace('-----END CERTIFICATE-----','')
        Config.templateRenderingDict['idp3EncryptionCertificateText'] = open('/etc/certs/idp-encryption.crt').read().replace('-----BEGIN CERTIFICATE-----','').replace('-----END CERTIFICATE-----','')

        print("Unpacking idp3")
        samlInstaller.unpack_idp3()
        samlInstaller.install_saml_libraries()

        #copy sealer.jks and sealer.kver
        self.copyFile(os.path.join(backup_dir, 'credentials/sealer.kver'), os.path.join(idp_dir, 'credentials'))
        self.copyFile(os.path.join(backup_dir, 'credentials/sealer.jks'), os.path.join(idp_dir, 'credentials'))
        
        #Recreate idp-metadata.xml with new format
        temp_fn = os.path.join(ces_dir, 'static/idp3/metadata/idp-metadata.xml')
        new_saml_meta_data = self.render_template(temp_fn)
        self.writeFile(saml_meta_data_fn, new_saml_meta_data)

        for prop_fn in ('idp.properties', 'ldap.properties', 'services.properties','saml-nameid.properties'):
            print("Updating", prop_fn)
            properties = self.render_template(os.path.join(ces_dir, 'static/idp3/conf', prop_fn))
            self.writeFile(os.path.join('/opt/shibboleth-idp/conf', prop_fn), properties)

        self.run(['cp', '-f', '/opt/dist/gluu/upgrades/saml-nameid.properties.vm', '/opt/gluu/jetty/identity/conf/shibboleth3/idp/'])
        self.run(['chown', '-R', 'jetty:jetty', '/opt/shibboleth-idp'])

    def update_radius(self):

        radius_dir = '/opt/gluu/radius'
        if not os.path.exists(radius_dir):
            return

        print("Updating Gluu Radius Server")
        
        self.setupObj.copyFile(os.path.join(ces_dir, 'static/radius/etc/init.d/gluu-radius'), '/etc/init.d')
        self.setupObj.run(['chmod', '+x', '/etc/init.d/gluu-radius'])

        radius_libs = os.path.join(self.app_dir, 'gluu-radius-libs.zip')
        radius_jar = os.path.join(self.app_dir, 'super-gluu-radius-server.jar')

        self.setupObj.run(['unzip', '-o', '-q', radius_libs, '-d', radius_dir ])
        self.setupObj.copyFile(radius_jar, radius_dir)

        self.setupObj.copyFile(os.path.join(ces_dir, 'static/radius/etc/default/gluu-radius'), self.setupObj.osDefault)


    def update_oxd(self):
        oxd_root = '/opt/oxd-server/'
        if not os.path.exists(oxd_root):
            return

        print("Updating oxd Server")
        self.setupObj.copyFile(
                    os.path.join(self.app_dir, 'oxd-server.jar'),
                    '/opt/oxd-server/lib'
                    )

        oxd_server_yml_fn = os.path.join(oxd_root, 'conf/oxd-server.yml')
        yml_str = self.setupObj.readFile(oxd_server_yml_fn)
        oxd_yaml = ruamel.yaml.load(yml_str, ruamel.yaml.RoundTripLoader)

        ip = self.setupObj.detect_ip()

        if os.path.exists(self.casa_base_dir) and hasattr(self, 'casa_oxd_host') and getattr(self, 'casa_oxd_host') in (Config.hostname, ip):

            write_oxd_yaml = False
            if 'bind_ip_addresses' in oxd_yaml:
                if not ip in oxd_yaml['bind_ip_addresses']:
                    oxd_yaml['bind_ip_addresses'].append(ip)
                    write_oxd_yaml = True
            else:
                for i, k in enumerate(oxd_yaml):
                    if k == 'storage':
                        break
                else:
                    i = 1
                oxd_yaml.insert(i, 'bind_ip_addresses',  [ip])
                write_oxd_yaml = True

            if write_oxd_yaml:
                yml_str = ruamel.yaml.dump(oxd_yaml, Dumper=ruamel.yaml.RoundTripDumper)
                self.setupObj.writeFile(oxd_server_yml_fn, yml_str)


            #create oxd certificate if not CN=hostname
            r = os.popen('/opt/jre/bin/keytool -list -v -keystore {}  -storepass {} | grep Owner'.format(oxd_yaml['server']['applicationConnectors'][0]['keyStorePath'], oxd_yaml['server']['applicationConnectors'][0]['keyStorePassword'])).read()
            for l in r.splitlines():
                res = re.search('CN=(.*?.),', l)
                if res:
                    cert_cn = res.groups()[0]
                    if cert_cn != Config.hostname:
                        self.setupObj.run([
                            self.setupObj.opensslCommand,
                            'req', '-x509', '-newkey', 'rsa:4096', '-nodes',
                            '-out', '/tmp/oxd.crt',
                            '-keyout', '/tmp/oxd.key',
                            '-days', '3650',
                            '-subj', '/C={}/ST={}/L={}/O={}/CN={}/emailAddress={}'.format(self.setupObj.countryCode, self.setupObj.state, self.setupObj.city, self.setupObj.orgName, self.setupObj.hostname, self.setupObj.admin_email),
                            ])

                        self.setupObj.run([
                            self.setupObj.opensslCommand,
                            'pkcs12', '-export',
                            '-in', '/tmp/oxd.crt',
                            '-inkey', '/tmp/oxd.key',
                            '-out', '/tmp/oxd.p12',
                            '-name', self.setupObj.hostname,
                            '-passout', 'pass:example'
                            ])

                        self.setupObj.run([
                            self.setupObj.cmd_keytool,
                            '-importkeystore',
                            '-deststorepass', 'example',
                            '-destkeypass', 'example',
                            '-destkeystore', '/tmp/oxd.keystore',
                            '-srckeystore', '/tmp/oxd.p12',
                            '-srcstoretype', 'PKCS12',
                            '-srcstorepass', 'example',
                            '-alias', self.setupObj.hostname,
                            ])

                        self.setupObj.backupFile(oxd_yaml['server']['applicationConnectors'][0]['keyStorePath'])
                        self.setupObj.run(['cp', '-f', '/tmp/oxd.keystore', oxd_yaml['server']['applicationConnectors'][0]['keyStorePath']])
                        self.setupObj.run(['chown', 'jetty:jetty', oxd_yaml['server']['applicationConnectors'][0]['keyStorePath']])

                        for f in ('/tmp/oxd.crt', '/tmp/oxd.key', '/tmp/oxd.p12', '/tmp/oxd.keystore'):
                            self.setupObj.run(['rm', '-f', f])
                        
            print("Restarting oxd-server")
            self.setupObj.run_service_command('oxd-server', 'stop')
            self.setupObj.run_service_command('oxd-server', 'start')

            print("Importing oxd certificate to cacerts")        
            self.setupObj.import_oxd_certificate()

    def update_casa(self):
        
        if not os.path.exists(self.casa_base_dir):
            return

        print("Updating casa")
        casa_config_dn = 'ou=casa,ou=configuration,o=gluu'
        casa_config_json = {}
        casa_cors_domains_fn = os.path.join(self.casa_base_dir, 'casa-cors-domains')
        casa_config_json_fn = os.path.join(self.setupObj.configFolder, 'casa.json')

        if os.path.exists(casa_config_json_fn):
            casa_config_json_s = self.setupObj.readFile(casa_config_json_fn)
            casa_config_json = json.loads(casa_config_json_s)

            if os.path.exists(casa_cors_domains_fn):
                casa_cors_domains = self.setupObj.readFile(casa_cors_domains_fn)
                casa_cors_domains_list = [l.strip() for l in casa_cors_domains.splitlines()]
                casa_config_json['allowed_cors_domains'] = casa_cors_domains_list

        casa_plugins_dir = os.path.join(self.casa_base_dir, 'plugins')
        self.setupObj.run_service_command('casa', 'stop')
        
        self.setupObj.run(['cp', '-f', os.path.join(self.app_dir, 'casa.war'),
                                    os.path.join(self.casa_base_dir, 'webapps')])

        account_linking = None
        
        # update plugins
        for plugin in glob.glob(os.path.join(casa_plugins_dir,'*.jar')):
            plugin_zip = zipfile.ZipFile(plugin, "r")
            menifest = plugin_zip.read('META-INF/MANIFEST.MF')
            for l in menifest.splitlines():
                ls = l.decode().strip()
                if ls.startswith('Plugin-Id'):
                    n = ls.find(':')
                    pid = ls[n+1:].strip()
                    if pid in self.casa_plugins:
                        jar_fn = os.path.join(self.app_dir, pid + '.jar')
                        self.setupObj.run(['rm', '-f', plugin])
                        self.setupObj.run(['cp', '-f', jar_fn, casa_plugins_dir])
                    if pid == 'account-linking':
                        account_linking = True

        if account_linking:
            self.setupObj.copyFile(
                    os.path.join(self.app_dir, 'casa.xhtml'),
                    os.path.join(self.setupObj.jetty_base, 'oxauth/custom/pages')
                    )
            
            scr = self.setupObj.readFile(os.path.join(self.app_dir, 'casa.py'))

            
            dbUtils.ldap_conn.modify(
                    'inum=BABA-CACA,ou=scripts,o=gluu', 
                    {'oxScript':  [ldap3.MODIFY_REPLACE, scr]}
                    )

            if casa_config_json:
                casa_config_json['basic_2fa_settings'] = {
                                    'autoEnable': False,
                                    'allowSelfEnableDisable': True,
                                    'min_creds': casa_config_json['min_creds_2FA']
                                    }

                casa_config_json['plugins_settings'] = {
                                    'strong-authn-settings': {
                                        'policy_2fa' : casa_config_json.get('policy_2fa',''),
                                        'trusted_dev_settings': casa_config_json.get('trusted_dev_settings', {}),
                                        'basic_2fa_settings': casa_config_json['basic_2fa_settings']
                                        }
                                    }

        if casa_config_json:

            casa_config_json_s = json.dumps(casa_config_json, indent=2)


            dbUtils.ldap_conn.search(
                            search_base=casa_config_dn,
                            search_scope=ldap3.BASE, 
                            search_filter='(objectClass=oxApplicationConfiguration)', 
                            attributes=['oxConfApplication']
                            )

            entry = {'objectClass': ['top', 'oxApplicationConfiguration'], 'ou': ['casa'], 'oxConfApplication': casa_config_json_s}

            if not dbUtils.ldap_conn.response:
                print("Importing casa configuration ldif")
                dbUtils.ldap_conn.add(casa_config_dn, attributes=entry)
            else:
                print("Modifying casa configuration ldif")
                dbUtils.ldap_conn.modify(
                        casa_config_dn, 
                        {'oxConfApplication':  [ldap3.MODIFY_REPLACE, casa_config_json_s]}
                        )


            self.setupObj.backupFile(casa_config_json_fn)
            #self.setupObj.run(['rm', '-f', casa_config_json_fn])


        def fix_oxConfApplication(oxConfApplication):
            if not oxConfApplication.get('oxd_config'):
                oxConfApplication['oxd_config'] = {}
                
            oxConfApplication['oxd_config']['authz_redirect_uri'] = 'https://{}/casa'.format(Config.hostname)
            oxConfApplication['oxd_config']['frontchannel_logout_uri'] = 'https://{}/casa/autologout'.format(Config.hostname)
            oxConfApplication['oxd_config']['post_logout_uri'] = 'https://{}/casa/bye.zul'.format(Config.hostname)

            
            if not oxConfApplication['oxd_config'].get('port'):
                oxConfApplication['oxd_config']['port'] = 8443
            if not oxConfApplication['oxd_config'].get('host'):
                oxConfApplication['oxd_config']['host'] = Config.hostname


        dbUtils.ldap_conn.search(
                search_base=casa_config_dn,
                search_scope=ldap3.BASE,
                search_filter='(objectclass=*)', attributes=['oxConfApplication']
            )

        result = dbUtils.ldap_conn.response

        if result:
            oxConfApplication = json.loads(result[0]['attributes']['oxConfApplication'][0])
            fix_oxConfApplication(oxConfApplication)
            dbUtils.ldap_conn.modify(
                    casa_config_dn, 
                    {'oxConfApplication':  [ldap3.MODIFY_REPLACE, json.dumps(oxConfApplication)]}
                    )

            self.casa_oxd_host = oxConfApplication['oxd_config']['host']


        self.setupObj.oxd_server_https = 'https://{}:{}'.format(oxConfApplication['oxd_config']['host'], oxConfApplication['oxd_config']['port'])

    def update_passport(self):

        if not os.path.exists(passportInstaller.gluu_passport_base):
            return

        backup_folder = passportInstaller.gluu_passport_base + '-back.' + os.urandom(3).hex() + '~'
        print("Updating Passport")
        print("Stopping passport server")
        passportInstaller.stop()

        self.run(['mv', passportInstaller.gluu_passport_base, backup_folder])

        self.run(['mkdir', '-p', passportInstaller.gluu_passport_base])

        passportInstaller.extract_passport()
        passportInstaller.extract_modules()
    
        log_dir = os.path.join(passportInstaller.gluu_passport_base, 'logs')

        if not os.path.exists(log_dir): 
            self.run(['mkdir',log_dir])

        # copy mappings
        for m_path in glob.glob(os.path.join(backup_folder, 'server/mappings/*.js')):
            with open(m_path) as f:
                fc = f.read()
                if re.search('profile["[\s\S]*"]', fc):
                    mfn = os.path.basename(m_path)
                    if not os.path.exists(os.path.join(passportInstaller.gluu_passport_base, 'server/mappings', mfn)):
                        self.copyFile(m_path, os.path.join(passportInstaller.gluu_passport_base, 'server/mappings'))

        #create empty log file
        log_file = os.path.join(log_dir, 'start.log')
        open(log_file,'w').close()

    def add_oxAuthUserId_pairwiseIdentifier(self):

        print("Adding oxAuthUserId to pairwiseIdentifier.")
        print("This may take several minutes depending on your user number")


        dbUtils.ldap_conn.search(
                        search_base='ou=people,o=gluu',
                        search_scope=ldap3.SUBTREE, 
                        search_filter='(objectClass=pairwiseIdentifier)', 
                        attributes=['*']
                        )
        result = dbUtils.ldap_conn.response
        for e in result:
            if not 'oxAuthUserId' in e['attributes']:
                for dne in dnutils.parse_dn(e['dn']):
                    if dne[0] == 'inum':
                        oxAuthUserId =  dne[1]
                        dbUtils.ldap_conn.modify(
                                e['dn'], 
                                {'oxAuthUserId': [ldap3.MODIFY_ADD, oxAuthUserId]}
                                )


    def fix_fido2(self):

        self.setupObj.renderTemplate(self.setupObj.fido2_dynamic_conf_json)
        self.setupObj.renderTemplate(self.setupObj.fido2_static_conf_json)

        self.setupObj.templateRenderingDict['fido2_dynamic_conf_base64'] = self.setupObj.generate_base64_ldap_file(self.setupObj.fido2_dynamic_conf_json)
        self.setupObj.templateRenderingDict['fido2_static_conf_base64'] = self.setupObj.generate_base64_ldap_file(self.setupObj.fido2_static_conf_json)
        self.setupObj.renderTemplate(self.setupObj.ldif_fido2)

        self.setupObj.run(['cp', self.setupObj.ldif_fido2, '/tmp'])
        ldif_fido2 = os.path.join('/tmp', os.path.basename(self.setupObj.ldif_fido2))


        dbUtils.ldap_conn.search(
                search_base='ou=fido2,ou=configuration,o=gluu', 
                search_scope=ldap3.BASE, 
                search_filter='(objectClass=*)', 
                attributes=['*']
                )
        if not dbUtils.ldap_conn.response:
            print("Importing fido2 configuration ldif")
            self.setupObj.import_ldif_opendj([ldif_fido2])

        dbUtils.ldap_conn.search(
                    search_base='ou=people,o=gluu', 
                    search_scope=ldap3.SUBTREE, 
                    search_filter='(objectclass=oxDeviceRegistration)', 
                    attributes=['*']
                    )

        result = dbUtils.ldap_conn.response
        if result:
            print("Populating personInum for fido2 entries. Number of entries: {}".format(len(result)))
            for entry in result:
                dn = entry['dn']
                if not 'personInum' in entry['attributes']:
                    for dnr in dnutils.parse_dn(dn):
                        if dnr[0] == 'inum':
                            inum = dnr[1]
                            dbUtils.ldap_conn.modify(
                                    dn, 
                                    {'personInum': [ldap3.MODIFY_ADD, inum]}
                                    )
                            break



    def updateAttributes(self):

        attributes_ldif_fn = os.path.join(ces_dir, 'templates/attributes.ldif')
        attributes_ldif = ldif_utils.myLdifParser(attributes_ldif_fn)
        attributes_ldif.parse()

        dn = 'inum=6049,ou=attributes,o=gluu'
        dbUtils.ldap_conn.search(
                search_base=dn, 
                search_scope=ldap3.BASE, 
                search_filter='(objectClass=*)', 
                attributes=['*']
                )
        result = dbUtils.ldap_conn.response
        if not 'user_permission' in result[0]['attributes'].get('oxAuthClaimName', []):
            print("Modifying attribute", dn)
            dbUtils.ldap_conn.modify(
                        dn,
                        {'oxAuthClaimName': [ldap3.MODIFY_ADD, 'user_permission']}
                        )

        dbUtils.ldap_conn.search(
                search_base='ou=attributes,o=gluu', 
                search_scope=ldap3.LEVEL, 
                search_filter='(objectClass=*)', 
                attributes=['inum']
                )
        result = dbUtils.ldap_conn.response

        current_attributes_list = [ e['dn'] for e in result ]

        for dn, entry in attributes_ldif.entries:
            if not dn in current_attributes_list:
                print("Adding attribute", dn)
                dbUtils.ldap_conn.add(dn, attributes=entry)



    def update_scopes(self):

        ldif_fn = os.path.join(ces_dir, 'templates/scopes.ldif')
        ldif_parser = ldif_utils.myLdifParser(ldif_fn)
        ldif_parser.parse()
        
        for dn, entry in ldif_parser.entries:
            dbUtils.ldap_conn.search(
                        search_base=dn, 
                        search_scope=ldap3.BASE, 
                        search_filter='(objectClass=*)', 
                        attributes=['*']
                        )
            if not dbUtils.ldap_conn.response:
                print("Adding scope", dn)
                dbUtils.ldap_conn.add(dn, attributes=entry)


    def update_default_settings(self):
        print("Updating /etc/default files")
        for service in ('casa', 'fido2', 'identity', 'idp', 'oxauth', 'oxauth-rp', 'scim'):
            default_fn = os.path.join('/etc/default', service)
            if os.path.exists(default_fn):
                print("Updating", default_fn)
                default_ = self.render_template(os.path.join(ces_dir, 'templates/jetty', service))
                self.writeFile(default_fn, default_)

updaterObj = GluuUpdater()

updaterObj.prepare_persist_changes()
updaterObj.fix_gluu_config()
updaterObj.update_ldap()
httpdinstaller.write_httpd_config()
print("Restarting Apache")
updaterObj.restart('apache2')
updaterObj.update_scripts()
updaterObj.updateAttributes()
updaterObj.update_scopes()
updaterObj.update_default_settings()
updaterObj.update_war_files()
updaterObj.update_shib()
updaterObj.update_passport()


"""
import code
code.interact(local=locals())
sys.exit()



updaterObj.update_radius()
updaterObj.update_casa()
updaterObj.update_oxd()
updaterObj.add_oxAuthUserId_pairwiseIdentifier()
updaterObj.fix_fido2()
updaterObj.setupObj.deleteLdapPw()
"""

print("\nUpgrade is finished. Please examine\n{}\nif something went wrong".format(paths.LOG_ERROR_FILE))
