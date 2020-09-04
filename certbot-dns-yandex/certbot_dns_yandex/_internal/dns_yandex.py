"""DNS Authenticator for Yandex DNS."""
import logging

from lexicon.providers import yandex
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://pddimp.yandex.ru/api2/admin/get_token'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Yandex DNS

    This Authenticator uses the Yandex DNS API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using Yandex for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='Yandex credentials INI file.')

    def more_info(self):  # pylint: disable=missing-function-docstring
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Yandex API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Yandex credentials INI file',
            {
                'auth_token': 'API key for Yandex account, obtained from {0}'.format(ACCOUNT_URL)
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_yandex_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_yandex_client().del_txt_record(domain, validation_name, validation)

    def _get_yandex_client(self):
        return _YandexLexiconClient(self.credentials.conf('auth_token'),
                                      self.ttl)


class _YandexLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the Yandex via Lexicon.
    """

    def __init__(self, auth_token, ttl):
        super(_YandexLexiconClient, self).__init__()

        config = dns_common_lexicon.build_lexicon_config('yandex', {
            'ttl': ttl,
        }, {
            'auth_token': auth_token
        })

        self.provider = yandex.Provider(config)

    def _handle_http_error(self, e, domain_name):
        hint = None
        if str(e).startswith('400 Client Error:'):
            hint = 'Are your Pdd Token value correct?'

        return errors.PluginError('Error determining zone identifier for {0}: {1}.{2}'
                                  .format(domain_name, e, ' ({0})'.format(hint) if hint else ''))
