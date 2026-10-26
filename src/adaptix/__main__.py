import sys

if __name__ == "__main__":
    if sys.argv[1:2] == ['recon']:
        from src.adaptix.local_inventory.cli import main
        raise SystemExit(main(sys.argv[2:]))
    else:
        from src.adaptix.main import main
        raise SystemExit(main())
