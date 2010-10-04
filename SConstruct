# Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys

# Borrowed from updater
# Protobuffer compilation
def ProtocolBufferEmitter(target, source, env):
  """ Inputs:
          target: list of targets to compile to
          source: list of sources to compile
          env: the scons environment in which we are compiling
      Outputs:
          target: the list of targets we'll emit
          source: the list of sources we'll compile"""
  output = str(source[0])
  output = output[0:output.rfind('.proto')]
  target = [
    output + '.pb.cc',
    output + '.pb.h',
  ]
  return target, source

def ProtocolBufferGenerator(source, target, env, for_signature):
  """ Inputs:
          source: list of sources to process
          target: list of targets to generate
          env: scons environment in which we are working
          for_signature: unused
      Outputs: a list of commands to execute to generate the targets from
               the sources."""
  commands = [
    '/usr/bin/protoc '
    ' --proto_path . ${SOURCES} --cpp_out .']
  return commands

proto_builder = Builder(generator = ProtocolBufferGenerator,
                        emitter = ProtocolBufferEmitter,
                        single_source = 1,
                        suffix = '.pb.cc')

env = Environment()

# setup sources
lib_sources = env.Split("""crypto.cc
                           platform.cc
                           secure_blob.cc
                           tpm.cc
                           tpm_init.cc
                           tpm_status.pb.cc
                           """)
client_sources = env.Split("""main.cc
                           """) + lib_sources

env.Append(
    CPPPATH=['.', '..'],
    CPPFLAGS=['-pie', '-fstack-protector-all', '-fPIC',
              '-fno-exceptions', '-O2', '-Wall', '-Werror'],
    LIBS = ['base', 'chromeos', 'crypto', 'rt', 'protobuf', 'pthread', 'tspi'],
)
for key in Split('CC CXX AR RANLIB LD NM CFLAGS CCFLAGS'):
  value = os.environ.get(key)
  if value != None:
    env[key] = value

# Fix issue with scons not passing some vars through the environment.
for key in Split('PKG_CONFIG_LIBDIR PKG_CONFIG_PATH SYSROOT'):
  if os.environ.has_key(key):
    env['ENV'][key] = os.environ[key]

env['BUILDERS']['ProtocolBuffer'] = proto_builder

env.Append(LIBPATH = ['.'])

env_lib = env.Clone()
env_lib.ProtocolBuffer('tpm_status.pb.cc', 'tpm_status.proto')
env_lib.Library('tpm_init', lib_sources)

