<?php

namespace Andig;

use Andig\CardDav\Backend;
use Sabre\VObject\Document;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Helper\ProgressBar;

trait DownloadTrait
{
    /**
     * Default list of card attributes to substitute
     *
     * @return array
     */
    public function getDefaultSubstitutes(): array
    {
        return ['PHOTO'];
    }

    /**
     * Download vcards from single provider
     *
     * @param OutputInterface $output
     * @param Backend $provider
     * @return Document[]
     */
    public function downloadProvider(OutputInterface $output, Backend $provider): array
    {
        $progress = new ProgressBar($output);
        $progress->start();
        $cards = download($provider, function () use ($progress) {
            $progress->advance();
        });
        $progress->finish();
        return $cards;
    }

    /**
     * Download vcards from all configured providers
     *
     * @param OutputInterface $output
     * @param bool $downloadImages
     * @param string[] $local
     * @return Document[]
     */
    public function downloadAllProviders(OutputInterface $output, bool $downloadImages, array $local = []): array
    {
        $vcards = [];

        foreach ($local as $file) {
            error_log("Reading vCard(s) from file ".$file);

            $provider = localProvider($file);
            $cards = $this->downloadProvider($output, $provider);

            error_log(sprintf("\nRead %d vCard(s)", count($cards)));
            $vcards = array_merge($vcards, $cards);
        }

        foreach ($this->config['server'] as $server) {
            error_log("Downloading vCard(s) from account ".$server['user']);

            $provider = backendProvider($server);
            if ($downloadImages) {
                $substitutes = $this->getDefaultSubstitutes();
                $provider->setSubstitutes($substitutes);
            }
            $cards = $this->downloadProvider($output, $provider);

            error_log(sprintf("\nDownloaded %d vCard(s)", count($cards)));
            $vcards = array_merge($vcards, $cards);
        }

        return $vcards;
    }

    /**
     * Dissolve the groups of iCloud contacts
     *
     * @param mixed[] $vcards
     * @return mixed[]
     */
    public function processGroups(array $vcards): array
    {
        $quantity = count($vcards);

        error_log("Dissolving groups (e.g. iCloud)");
        $vcards = dissolveGroups($vcards);
        error_log(sprintf("Dissolved %d group(s)", $quantity - count($vcards)));

        return $vcards;
    }

    /**
     * Filter included/excluded vcards
     *
     * @param mixed[] $vcards
     * @return mixed[]
     */
    public function processFilters(array $vcards): array
    {
        $quantity = count($vcards);

        error_log(sprintf("Filtering %d vCard(s)", $quantity));
        $vcards = filter($vcards, $this->config['filters']);
        error_log(sprintf("Filtered %d vCard(s)", $quantity - count($vcards)));

        return $vcards;
    }
}
