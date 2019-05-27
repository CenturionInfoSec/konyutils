#!/usr/bin/env python3

import click

import base64

import os

import pathlib

import frida

import shutil

import sys

from zipfile import ZipFile

from tabulate import tabulate

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


IPA_FILE = None
OUT_DIR = None
IV = b"0000000000000000"


@click.command()
@click.argument("infile", type=click.Path())
@click.argument("package_name", type=str)
@click.argument("outdir", type=click.Path())
def cli(infile, package_name, outdir):

    global IPA_FILE
    global OUT_DIR

    IPA_FILE = infile
    OUT_DIR = outdir

    os.makedirs(outdir, exist_ok=True)

    devices = frida.get_device_manager().enumerate_devices()
    device = get_device(devices)

    pid = device.spawn([package_name])
    process = device.attach(pid)

    with open(os.path.join(sys.path[0], "hook.js"), "r") as f:
        script = process.create_script(f.read())

    script.on("message", process_message)
    script.load()

    device.resume(pid)
    input()


def process_message(message, data):
    if message["type"] == "send":

        if message["payload"] == "iv":
            click.echo("Found iv: {}".format(base64.b64encode(data)))
            global IV
            IV = data

        if message["payload"] == "key":
            click.echo("Found key: {}".format(base64.b64encode(data)))
            click.echo("Unpacking IPA.")
            decrypt_assets(data)
            os._exit(1)


def decrypt_assets(key):
    with ZipFile(IPA_FILE, "r") as zf:
        for f in zf.infolist():
            if "/JSScripts/" in f.filename:
                of_name = os.path.basename(f.filename)

                if of_name == "":
                    continue

                with zf.open(f.filename) as jsfile:
                    data = decrypt_file(jsfile, key, IV)
                    with open(
                            os.path.join(OUT_DIR, "{}".format(of_name)), "wb"
                    ) as of:
                        of.write(data)


def decrypt_file(f, key, iv):
    backend = default_backend()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    ciphertext = f.read()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(plaintext) + unpadder.finalize()


def get_device(devices):
    click.echo("Available devices:")
    list_devices(devices)

    click.echo()
    click.echo("Select device (by index): ", nl=False)
    selection = input()

    try:
        return devices[int(selection)]
    except:
        click.echo("Please enter a valid device selection...")
        os._exit(1)


def list_devices(devices):
    devices_info = [(i.id, i.name, i.type) for i in devices]
    click.echo(tabulate(
        devices_info, headers=["id", "name", "type"], showindex=True))


if __name__ == "__main__":
    cli()
