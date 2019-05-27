#!/usr/bin/env python3

import click

import base64

import os

import pathlib

import frida

import shutil

import sys

from tabulate import tabulate

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


APK_FILE = None
OUT_DIR = None


@click.command()
@click.argument("infile", type=click.Path())
@click.argument("package_name", type=str)
@click.argument("outdir", type=click.Path())
def cli(infile, package_name, outdir):

    global APK_FILE
    global OUT_DIR

    APK_FILE = infile
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
        if message["payload"] == "key":
            click.echo("Found key: {}".format(base64.b64encode(data)))
            click.echo("Unpacking APK.")
            decrypt_assets(data)
            os._exit(1)


def decrypt_assets(key):
    os.system("apktool d -r -s -o tmpdir {} > /dev/null".format(APK_FILE))

    iv = b"0000000000000000"

    p = pathlib.Path("tmpdir/assets/js")
    p_iter = p.iterdir()

    f = next(p_iter)
    data = decrypt_file(f.open("rb"), key, iv)

    if data[0] == 0x50 and data[1] == 0x4b:
        with open(os.path.join(OUT_DIR, "{}.zip".format(f.name)), "wb") as of:
            of.write(data)
    else:
        iv = b"abcd1234efgh5678"
        with open(os.path.join(OUT_DIR, "{}.zip".format(f.name)), "wb") as of:
            of.write(decrypt_file(f.open("rb"), key, iv))

    for f in p_iter:
        with open(os.path.join(OUT_DIR, "{}.zip".format(f.name)), "wb") as of:
            of.write(decrypt_file(f.open("rb"), key, iv))

    shutil.rmtree("tmpdir")


def decrypt_file(f, key, iv):
    backend = default_backend()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    ciphertext = f.read()
    return decryptor.update(ciphertext) + decryptor.finalize()


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
