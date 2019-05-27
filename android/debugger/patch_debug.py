#!/usr/bin/env python3

import click

import os

import sys

import shutil


@click.command()
@click.argument("infile", type=click.Path(exists=True))
@click.argument("libkonyjsvm", type=click.Path(exists=True))
@click.argument("outfile", type=click.Path(exists=False))
def cli(infile, libkonyjsvm, outfile):
    os.system("apktool d -r -s -o tmpapk {} > /dev/null".format(infile))
    shutil.copyfile(libkonyjsvm, "tmpapk/lib/armeabi-v7a/libkonyjsvm.so")
    os.system("apktool b -o {} tmpapk > /dev/null".format(outfile))
    shutil.rmtree("tmpapk")


if __name__ == "__main__":
    cli()
