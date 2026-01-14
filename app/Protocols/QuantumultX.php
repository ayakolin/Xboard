<?php

namespace App\Protocols;

use App\Support\AbstractProtocol;
use App\Models\Server;
class QuantumultX extends AbstractProtocol
{
    public $flags = ['quantumult%20x', 'quantumult-x'];
    public $allowedProtocols = [
        Server::TYPE_SHADOWSOCKS,
        Server::TYPE_VMESS,
        Server::TYPE_TROJAN,
        Server::TYPE_VLESS,
    ];
    protected $protocolRequirements = [
        'quantumult-x' => [
            'vless' => [
                'base_version' => '1.5.0',
                'protocol_settings.flow' => [
                    'xtls-rprx-vision' => '1.5.5'
                ],
                'protocol_settings.tls' => [
                    '2' => '1.5.5' // Reality
                ]
            ]
        ],
        'quantumult%20x' => [
            'vless' => [
                'base_version' => '1.5.0',
                'protocol_settings.flow' => [
                    'xtls-rprx-vision' => '1.5.5'
                ],
                'protocol_settings.tls' => [
                    '2' => '1.5.5' // Reality
                ]
            ]
        ]
    ];
    public function handle()
    {
        $servers = $this->servers;
        $user = $this->user;
        $uri = '';
        foreach ($servers as $item) {
            if ($item['type'] === Server::TYPE_SHADOWSOCKS) {
                $uri .= self::buildShadowsocks($item['password'], $item);
            }
            if ($item['type'] === Server::TYPE_VMESS) {
                $uri .= self::buildVmess($item['password'], $item);
            }
            if ($item['type'] === Server::TYPE_TROJAN) {
                $uri .= self::buildTrojan($item['password'], $item);
            }
            if ($item['type'] === Server::TYPE_VLESS) {
                $uri .= self::buildVless($item['password'], $item);
            }
        }
        return response(base64_encode($uri))
            ->header('content-type', 'text/plain')
            ->header('subscription-userinfo', "upload={$user['u']}; download={$user['d']}; total={$user['transfer_enable']}; expire={$user['expired_at']}");
    }
    public static function buildShadowsocks($password, $server)
    {
        $protocol_settings = $server['protocol_settings'];
        $password = data_get($server, 'password', $password);
        $config = [
            "shadowsocks={$server['host']}:{$server['port']}",
            "method={$protocol_settings['cipher']}",
            "password={$password}",
            'fast-open=true',
            'udp-relay=true',
            "tag={$server['name']}"
        ];
        if (data_get($protocol_settings, 'plugin') && data_get($protocol_settings, 'plugin_opts')) {
            $plugin = data_get($protocol_settings, 'plugin');
            $pluginOpts = data_get($protocol_settings, 'plugin_opts', '');
            // 解析插件选项
            $parsedOpts = collect(explode(';', $pluginOpts))
                ->filter()
                ->mapWithKeys(function ($pair) {
                    if (!str_contains($pair, '=')) {
                        return [];
                    }
                    [$key, $value] = explode('=', $pair, 2);
                    return [trim($key) => trim($value)];
                })
                ->all();
            switch ($plugin) {
                case 'obfs':
                    $config[] = "obfs={$parsedOpts['obfs']}";
                    if (isset($parsedOpts['obfs-host'])) {
                        $config[] = "obfs-host={$parsedOpts['obfs-host']}";
                    }
                    if (isset($parsedOpts['path'])) {
                        $config[] = "obfs-uri={$parsedOpts['path']}";
                    }
                    break;
            }
        }
        $uri = implode(',', $config);
        $uri .= "\r\n";
        return $uri;
    }

    public static function buildVmess($uuid, $server)
    {
        $protocol_settings = $server['protocol_settings'];
        $config = [
            "vmess={$server['host']}:{$server['port']}",
            'method=chacha20-poly1305',
            "password={$uuid}",
            'fast-open=true',
            'udp-relay=true',
            "tag={$server['name']}"
        ];

        if (data_get($protocol_settings, 'tls')) {
            if (data_get($protocol_settings, 'network') === 'tcp')
                array_push($config, 'obfs=over-tls');
            if (data_get($protocol_settings, 'tls_settings')) {
                if (data_get($protocol_settings, 'tls_settings.allow_insecure'))
                    array_push($config, 'tls-verification=' . ($protocol_settings['tls_settings']['allow_insecure'] ? 'false' : 'true'));
                if (data_get($protocol_settings, 'tls_settings.server_name'))
                    $host = data_get($protocol_settings, 'tls_settings.server_name');
            }
        }
        if (data_get($protocol_settings, 'network') === 'ws') {
            if (data_get($protocol_settings, 'tls'))
                array_push($config, 'obfs=wss');
            else
                array_push($config, 'obfs=ws');
            if (data_get($protocol_settings, 'network_settings')) {
                if (data_get($protocol_settings, 'network_settings.path'))
                    array_push($config, "obfs-uri={$protocol_settings['network_settings']['path']}");
                if (data_get($protocol_settings, 'network_settings.headers.Host') && !isset($host))
                    $host = data_get($protocol_settings, 'network_settings.headers.Host');
            }
        }
        if (isset($host)) {
            array_push($config, "obfs-host={$host}");
        }

        $uri = implode(',', $config);
        $uri .= "\r\n";
        return $uri;
    }

    public static function buildTrojan($password, $server)
    {
        $protocol_settings = $server['protocol_settings'];
        $config = [
            "trojan={$server['host']}:{$server['port']}",
            "password={$password}",
            'over-tls=true',
            $protocol_settings['server_name'] ? "tls-host={$protocol_settings['server_name']}" : "",
            // Tips: allowInsecure=false = tls-verification=true
            $protocol_settings['allow_insecure'] ? 'tls-verification=false' : 'tls-verification=true',
            'fast-open=true',
            'udp-relay=true',
            "tag={$server['name']}"
        ];
        $config = array_filter($config);
        $uri = implode(',', $config);
        $uri .= "\r\n";
        return $uri;
    }
    public static function buildVless($uuid, $server)
    {
        $protocol_settings = $server['protocol_settings'];
        $config = [
            "vless={$server['host']}:{$server['port']}",
            "method=none",
            "password={$uuid}",
            'fast-open=true',
            'udp-relay=true',
            "tag={$server['name']}"
        ];
        //flow
        if (data_get($protocol_settings, 'flow')) {
            array_push($config, "vless-flow={$protocol_settings['flow']}");
        }
        // TLS/Reality
        switch (data_get($protocol_settings, 'tls')) {
            case 1:
                switch (data_get($protocol_settings, 'network')) {
                    case 'tcp':
                        array_push($config, 'obfs=over-tls');
                        break;
                    case 'ws':
                        array_push($config, 'obfs=wss');
                        if ($path = data_get($protocol_settings, 'network_settings.path')) {
                            array_push($config, "obfs-uri={$path}");
                        }
                        break;
                }
                if ($serverName = data_get($protocol_settings, 'tls_settings.server_name')) {
                    array_push($config, "obfs-host={$serverName}");
                }
                break;
            case 2:
                switch (data_get($protocol_settings, 'network')) {
                    case 'tcp':
                        array_push($config, 'obfs=over-tls');
                        break;
                    case 'ws':
                        array_push($config, 'obfs=wss');
                        if ($path = data_get($protocol_settings, 'network_settings.path')) {
                            array_push($config, "obfs-uri={$path}");
                        }
                        break;
                }
                if ($serverName = data_get($protocol_settings, 'reality_settings.server_name')) {
                    array_push($config, "obfs-host={$serverName}");
                }
                if ($pubkey = data_get($protocol_settings, 'reality_settings.public_key')) {
                    array_push($config, "reality-base64-pubkey={$pubkey}");
                }
                if ($shortid = data_get($protocol_settings, 'reality_settings.short_id')) {
                    array_push($config, "reality-hex-shortid={$shortid}");
                }
                break;
            default:
                switch (data_get($protocol_settings, 'network')) {
                    case 'http':
                        array_push($config, 'obfs=http');
                        if ($path = data_get($protocol_settings, 'network_settings.path')) {
                            array_push($config,"obfs-uri={$path}");
                        }
                        if ($host = data_get($protocol_settings, 'network_settings.host', $server['host'])) {
                            array_push($config,"obfs-host={$host}");
                        }
                        break;
                    case 'ws':
                        array_push($config, 'obfs=ws');
                        if ($path = data_get($protocol_settings, 'network_settings.path')) {
                            array_push($config,"obfs-uri={$path}");
                        }
                        if ($host = data_get($protocol_settings, 'network_settings.host', $server['host'])) {
                            array_push($config,"obfs-host={$host}");
                        }
                        break;
                }
                break;
        }
        $uri = implode(',', $config);
        $uri .= "\r\n";
        return $uri;
    }
}
