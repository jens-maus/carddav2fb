<?php

use \Andig\FritzBox\Converter;
use \PHPUnit\Framework\TestCase;
use Sabre\VObject;

class ConverterTest extends TestCase
{
    /** @var Converter */
    public $converter;

    /** @var SimpleXMLElement */
    public $contact;

    public function setUp()
    {
        $this->converter = new Converter($this->defaultConfig());
        $this->contact = $this->defaultContact();
    }

    private function defaultConfig(): array
    {
        return [
            'conversions' => [
                'phoneTypes' => [
                    'WORK' => 'work',
                    'HOME' => 'home',
                    'CELL' => 'mobile',
                    'FAX' => 'fax_work'
                ],
                'realName' => [],
            ],
        ];
    }

    private function defaultContact()
    {
        $c = new VObject\Component\VCard([
            'UID'  => 'uid',
        ]);
        $c->add('TEL', '1', ['type' => 'other']);

        return $c;
    }

    public function testDefaultContact()
    {
        $res = $this->converter->convert($this->contact);
        $this->assertInternalType('array', $res);
        $this->assertCount(1, $res);

        $contact = $res[0];
        $this->assertInstanceOf(SimpleXMLElement::class, $contact->person);
        $this->assertInstanceOf(SimpleXMLElement::class, $contact->telephony);
        $this->assertInstanceOf(SimpleXMLElement::class, $contact->telephony->number);
    }

    public function testSkipContactWithoutPhone()
    {
        unset($this->contact->TEL);

        $res = $this->converter->convert($this->contact);
        $this->assertCount(0, $res);
    }

    public function testEmptyPropertyReplacement()
    {
        $res = $this->converter->convert($this->contact);
        $this->assertCount(1, $res);

        $contact = $res[0];
        $this->assertEquals('', (string)$contact->person->realName);
    }

    public function contactPropertiesProvider(): array
    {
        return [
            [
                [
                    'firstname' => 'foo',
                    'lastname' => 'bar',
                    'organization' => 'orga',
                    'fullname' => 'full',
                ],
                'bar, foo'
            ],
            [
                [
                    'organization' => 'orga',
                    'fullname' => 'full',
                ],
                'orga'
            ],
            [
                [
                    'fullname' => 'full',
                ],
                'full'
            ],
        ];
    }

    /**
     * @dataProvider contactPropertiesProvider
     */
    public function testPropertyReplacement(array $properties, string $realName)
    {
        foreach ($properties as $key => $value) {
            $sabreKey = strtoupper($key);
            $this->contact->$sabreKey = $value;
        }

        // replacement config
        $config = $this->defaultConfig();
        $config['conversions']['realName'] = [
            '{lastname}, {firstname}',
            '{organization}',
            '{fullname}'
        ];

        $res = (new Converter($config))->convert($this->contact);
        $this->assertCount(1, $res);

        $contact = $res[0];
        $this->assertEquals($realName, (string)$contact->person->realName);
    }

    public function testPhoneTypeAreMappedAndOrdered()
    {
        unset($this->contact->TEL);
        $idx = 0;
        $conversions = $this->defaultConfig()['conversions'];
        foreach ($conversions['phoneTypes'] as $key => $value) {
            //$phoneType = sprintf('foo;%s;bar', strtolower($key));
            $this->contact->add('TEL',(string)$idx++ , ['type' => $key]);
        }

        $res = $this->converter->convert($this->contact);
        $this->assertCount(1, $res);

        $contact = $res[0];
        $this->assertCount(count($conversions['phoneTypes']), $contact->telephony->children());

        $idx = 0;
        foreach ($conversions['phoneTypes'] as $key => $value) {
            $number = $contact->telephony->children()[$idx];
            $this->assertEquals($value, (string)$number['type']);
            $this->assertEquals((string)$idx++, (string)$number);
        }
    }

    public function testFaxIsMapped()
    {
        unset($this->contact->TEL);
        $this->contact->add('TEL', '2', ['type' => 'fax']);

        $res = $this->converter->convert($this->contact);
        $this->assertCount(1, $res);

        $contact = $res[0];
        $this->assertCount(1, $contact->telephony->children());

        $faxNumber = $contact->telephony->children()[0]; // 1st number
        $this->assertEquals('fax_work', (string)$faxNumber['type']);
    }

    public function testVanityAndQuickdialNumbers()
    {
        unset($this->contact->TEL);
        $this->contact->add('TEL', '1', ['type' => 'other']);
        $this->contact->add('TEL', '2', ['type' => 'pref']);
        $this->contact->{'X-FB-QUICKDIAL'} = 'quickdial';
        $this->contact->{'X-FB-VANITY'} = 'vanity';

        $res = $this->converter->convert($this->contact);
        $this->assertCount(1, $res);

        $contact = $res[0];
        $this->assertCount(2, $contact->telephony->children());

        // first number without pref/vanity
        $vanityNumber = $contact->telephony->children()[0];
        $this->assertNull($vanityNumber['quickdial']);
        $this->assertNull($vanityNumber['vanity']);

        // second number with pref/vanity
        $vanityNumber = $contact->telephony->children()[1];
        $this->assertEquals('quickdial', (string)$vanityNumber['quickdial']);
        $this->assertEquals('vanity', (string)$vanityNumber['vanity']);
    }

    public function testMoreThan10PhoneNumbers()
    {
        unset($this->contact->TEL);
        for ($i=1; $i<=18; $i++) {
            $this->contact->add('TEL', (string)$i, ['type' => 'other']);
        }

        $res = $this->converter->convert($this->contact);
        $this->assertCount(2, $res);

        foreach ($res as $idx => $contact) {
            for ($i=1; $i<=9; $i++) {
                $expect = 9*$idx + $i;
                $this->assertContains((string)$expect, $contact->telephony->number);
            }
        }
    }
}
