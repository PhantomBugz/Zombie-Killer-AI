from zombie_killer_engine.parent_watch import install_broker_liveness_watch

if __name__ == "__main__":
    install_broker_liveness_watch()
    from zombie_killer_engine.cli import main

    main()
