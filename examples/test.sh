#!/bin/bash

run_make()
{
        #如果该目录下存在Makefile
        if [ -f "Makefile" ]; then
            pwd;
            make || exit 1;
        fi
}

testmakes()
{
        cd $1;
        run_make;
        # shellcheck disable=SC2045
        for x in $(ls .)
        do
                if [ -d "$x" ];then
                        testmakes $x;
                        cd ..
                fi
            
        done
}

testmakes .