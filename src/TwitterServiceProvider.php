<?php
namespace Blimp\Accounts;

use Pimple\ServiceProviderInterface;
use Pimple\Container;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;

class TwitterServiceProvider implements ServiceProviderInterface {
    public function register(Container $api) {
        $api->extend('blimp.extend', function ($status, $api) {
            if($status) {
                if($api->offsetExists('config.root')) {
                    $api->extend('config.root', function ($root, $api) {
                        $tb = new TreeBuilder();

                        $rootNode = $tb->root('twitter');

                        $rootNode
                            ->children()
                                ->scalarNode('consumer_key')->cannotBeEmpty()->end()
                                ->scalarNode('consumer_secret')->cannotBeEmpty()->end()
                            ->end()
                        ;

                        $root->append($rootNode);

                        return $root;
                    });
                }
            }

            return $status;
        });
    }
}
