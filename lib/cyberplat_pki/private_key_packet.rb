module CyberplatPKI
  class PrivateKeyPacket < KeyPacket
    def self.load(io, context)
      key = super

      cipher = io.readbyte
      raise "CyberplatPKI: CRYPT_ERR_INVALID_PACKET_FORMAT (unsupported private key cipher: #{cipher})" if cipher != 1 # IDEA-CFB + MD5

      iv = io.read 8
      context.decrypt iv

      public_key = key.key
      key.key = OpenSSL::PKey::RSA.new

      io.cipher = context
      io.checksum = 0

      d = io.read_mpi
      p = io.read_mpi
      q = io.read_mpi
      _ = io.read_mpi

      calculated_checksum = io.checksum

      key.key.set_factors(p, q)
      key.key.set_key(public_key.n, public_key.e, d)

      io.checksum = nil
      io.cipher = nil

      checksum, = io.read(2).unpack('n')

      if checksum != calculated_checksum
        raise "CyberplatPKI: CRYPT_ERR_INVALID_PASSWD (invalid MPI checksum. Expected #{checksum.to_s 16}, calculated #{calculated_checksum.to_s 16})"
      end

      dmp1 = key.key.d % (key.key.p - 1)
      dmq1 = key.key.d % (key.key.q - 1)
      iqmp = key.key.q.mod_inverse key.key.p

      key.key.set_crt_params(dmp1, dmq1, iqmp)
      # jruby-openssl requires public key parameters to be set LAST

      # key.key.n = public_key.n
      # key.key.e = public_key.e

      key
    end

    def save(io, context)
      super

      raise NotImplementedError, 'CyberplatPKI: PrivateKeyPacket#save is not implemented'
    end
  end
end
