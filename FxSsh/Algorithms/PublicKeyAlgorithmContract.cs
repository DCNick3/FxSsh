﻿using System;
using System.Diagnostics.Contracts;

namespace FxSsh.Algorithms
{
    [ContractClassFor(typeof(PublicKeyAlgorithm))]
    internal abstract class PublicKeyAlgorithmContract : PublicKeyAlgorithm
    {
        public override string Name => throw new NotImplementedException();

        public override PublicKeyAlgorithm ImportInternalBlob(byte[] bytes)
        {
            Contract.Requires(bytes != null);

            throw new NotImplementedException();
        }

        public override PublicKeyAlgorithm ImportKeyAndCertificatesData(byte[] data)
        {
            Contract.Requires(data != null);

            throw new NotImplementedException();
        }

        public override byte[] ExportKeyAndCertificatesData()
        {
            throw new NotImplementedException();
        }

        public override bool VerifyData(byte[] data, byte[] signature)
        {
            Contract.Requires(data != null);
            Contract.Requires(signature != null);

            throw new NotImplementedException();
        }

        public override byte[] SignData(byte[] data)
        {
            Contract.Requires(data != null);

            throw new NotImplementedException();
        }
    }
}