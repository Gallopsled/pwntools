#!/usr/bin/env ruby

require 'rubygems'
require 'fileutils'
require 'filemagic'

@@level = 0
@@max_level = 0
@@deepest = ''

class Unpacker
  def initialize filename, indent = ''
    @filename = filename.to_s
    @indent = "#{indent}  "
    @@level += 1
    @@max_level = @@level > @@max_level ? @@level : @@max_level

    magic = FileMagic.new

    # Determine file type, and proceed accordingly.
    case magic.file @filename
      when /^ELF/
        elf
      when /^ASCII/
        ascii
      when /^gzip/
        extract 'gzip', 'gz'
      when /^7-zip/
        extract '7zip', '7z'
      when /^POSIX tar/
        extract 'tar', 'tar'
      when /^bzip2/
        extract 'bzip2', 'bz2'
      when /^compress/
        extract 'compress', 'compress'
      when /^Zip/
        extract 'zip', 'zip'
      when /^ARJ/
        arj
      when /^lzop/
        lzop
      when /^ARC/
        arc
      when /^XZ/
        xz
      when /^rzip/
        rzip
      else
        puts "#{@indent}#{filename}: #{magic.file @filename}"
    end

    magic.close

    @@level -= 1
    @@deepest = "#{FileUtils.pwd}" if @@level >= @@max_level - 1
  end



private

  # Try running all arguments on ELF.
  def elf
    puts "#{@indent}#{@filename}: ELF"

    # Fetch arguments from .rodata section of ELF, skip irrelevant parts.
    args = `objdump -s -j .rodata #{@filename}`.split("\n").collect { |line|
      line.split('  ').reject { |arg| arg == '' or arg == ' ' }.last
    }.compact.join.split('.').compact.collect { |arg|
      words = arg.split
      words.join unless words.first == '%s' or words.first == 'rodata:' or words.last == 'section' or words.join == ''
    }.compact

    # TODO: Run ELF without arguments

    # Run ELF with each argument, unpack each resulting output in new directory
    File.chmod 0755, @filename
    args.each do |arg|
      dir = "arg-#{arg}/"
      filename = "arg-#{arg}"
      FileUtils.mkdir dir
      `./#{@filename} #{arg} > #{dir}/#{filename}`
      FileUtils.cd dir
      Unpacker.new filename, @indent
      FileUtils.cd '..'
    end
  end



  # Assume ASCII file is base64, and decode.
  def ascii
    dir = 'base64/'
    filename = "#{@filename}.txt"
    FileUtils.mv @filename, filename
    puts "#{@indent}#{filename}: ASCII"
    FileUtils.mkdir dir
    `base64 -di #{filename} > #{dir}/#{@filename} 2> stderr`
    FileUtils.cd dir
    Unpacker.new @filename, @indent
    FileUtils.cd '..'
  end



  # Extract supported file using 7zip, unpack each resulting file in new directory
  def extract type, extension
    dir = "#{type}/"
    filename = "#{@filename}.#{extension}"
    FileUtils.mv @filename, filename
    puts "#{@indent}#{filename}: #{type}"
    FileUtils.mkdir dir
    filename = `7za -o#{dir} e #{filename}`.split('Extracting  ').last.split.first
    FileUtils.cd dir
    begin
      Unpacker.new filename, @indent
    rescue
    end
    FileUtils.cd '..'
  end



  # Unpack lzop file using 7-zip, unpack each resulting file in new directory
  def lzop
    dir = 'lzop/'
    filename = "#{@filename}.lzo"
    FileUtils.mv @filename, filename
    puts "#{@indent}#{filename}: lzop"
    FileUtils.mkdir dir
    `lzop -p#{dir} -d #{filename}`
    FileUtils.cd dir
    Unpacker.new @filename, @indent
    FileUtils.cd '..'
  end



  def arc
    dir = 'arc/'
    filename = "#{@filename}.arc"
    FileUtils.mv @filename, filename
    puts "#{@indent}#{filename}: arc"
    FileUtils.mkdir dir
    filename = `arc e #{filename}`.split('Extracting file: ').last.split.first
    FileUtils.mv filename, "#{dir}/#{filename}"
    FileUtils.cd dir
    Unpacker.new filename, @indent
    FileUtils.cd '..'
  end



  def rzip
    dir = 'rzip/'
    filename = "#{@filename}.rz"
    FileUtils.mv @filename, filename
    puts "#{@indent}#{filename}: rzip"
    FileUtils.mkdir dir
    `rzip -dk #{filename}`
    FileUtils.mv @filename, "#{dir}/#{@filename}"
    FileUtils.cd dir
    Unpacker.new @filename, @indent
    FileUtils.cd '..'
  end



  def xz
    dir = 'xz/'
    filename = "#{@filename}.xz"
    FileUtils.mv @filename, filename
    puts "#{@indent}#{filename}: xz"
    FileUtils.mkdir dir
    `xz -dk #{filename}`
    FileUtils.mv @filename, "#{dir}/#{@filename}"
    FileUtils.cd dir
    Unpacker.new @filename, @indent
    FileUtils.cd '..'
  end



  def arj
    dir = 'arj/'
    filename = "#{@filename}.arj"
    FileUtils.mv @filename, filename
    puts "#{@indent}#{filename}: arj"
    FileUtils.mkdir dir
    filenames = `arj e #{filename}`.split('Extracting ').collect { |line| line.split.first }[1..-1]
    filenames.each do |filename|
      FileUtils.mv filename, "#{dir}/#{filename}"
    end
    FileUtils.cd dir
    filenames.each do |filename|
      `cat #{filename} >> #{@filename}`
    end
    Unpacker.new @filename, @indent
    FileUtils.cd '..'
  end
end

# Create directory "#{file}-unpack", and copy file to that directory.
if ARGV[0]
  dir = "#{ARGV[0]}-unpack/"
  puts '-----------'
  begin
  FileUtils.rm_r dir
  rescue
  end
  FileUtils.mkdir dir
  FileUtils.cp ARGV[0], "#{dir}#{ARGV[0]}"
  FileUtils.cd dir
  Unpacker.new ARGV[0]
  FileUtils.cd '..'
  puts "--------\nDEEPEST:\n\n#{@@deepest}\n"
else
  puts 'Usage: unpacker.rb <file>'
end
