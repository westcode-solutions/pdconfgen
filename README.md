
[![Build Status](https://travis-ci.org/westcode-solutions/pdconfgen.svg?branch=master)](https://travis-ci.org/westcode-solutions/pdconfgen)

# pdconfgen

Generate example PD Sentry configuration by sending an snmp trap to pdconfgen.

## Installation

* Install rust and cargo
https://www.rust-lang.org/tools/install

* Checkout source
```
git clone 
````

## Build

```
cargo build --release
```

## Run

```
./target/release/pdconfgen
```

## Test

* SNMPv1 Trap

```
snmptrap -v 1 -c public 127.0.0.1:34254 1.3.6.1.4.1.1824 192.168.2.116 6 1 0 1.3.6.1.4.1.1824.1.0.0.1 string "This is a string" 1.3.6.1.4.1.1824.1.0.0.1 c 3345556 1.3.6.1.4.1.1824.1.0.0.1 uint 12343212 1.3.6.1.4.1.1824.1.0.0.1 int -123456799 1.3.6.1.4.1.1824.1.0.0.1 address "100.200.123.111" 1.3.6.1.4.1.1824.1.0.0.1 oid 1.2.3.4.5.6.7.8.9 1.3.6.1.4.1.1824.1.0.0.1 time 2233121 1.3.6.1.4.1.1824.1.0.0.1 int -199
```

* SNMPv2 Trap/Inform

```
snmptrap -v 2c -c public 127.0.0.1:34254 0 1.3.6.1.4.1.1824.0.1 1.3.6.1.4.1.1824.1.0.0.1 string "This is a string" 1.3.6.1.4.1.1824.1.0.0.1 c 3345556 1.3.6.1.4.1.1824.1.0.0.1 uint 12343212 1.3.6.1.4.1.1824.1.0.0.1 int -123456799 1.3.6.1.4.1.1824.1.0.0.1 address "100.200.123.111" 1.3.6.1.4.1.1824.1.0.0.1 oid 1.2.3.4.5.6.7.8.9 1.3.6.1.4.1.1824.1.0.0.1 time 2233121 1.3.6.1.4.1.1824.1.0.0.1 int -199
```
