build             :; forge build
clean             :; forge clean
clean-all         :; forge clean; rm ./logs/*.log
clean-logs        :; rm ./logs/*.log
format-logs       :; ./test/invariant/scripts/clean_logs.py
.PHONY: test
test              :; make clean; make invariant
invariant         :; ./test/invariant/scripts/invariant.sh --seed=$(seed) --runs=$(runs) --depth=$(depth) --v=$(v) --mt=$(mt) --mc=$(mc) --type="invariant" --leap=$(leap)
invariant-nc      :; ./test/invariant/scripts/invariant.sh --seed=$(seed) --runs=$(runs) --depth=$(depth) --v=$(v) --mt=$(mt) --mc=$(mc) --type="invariant" --leap=$(leap) "nc"
regression        :; ./test/invariant/scripts/invariant.sh --mt=$(or $(mt), regression) --v=$(or $(v), 4) --mc=$(mc) "nc" --type="regression"
gen-regression    :; ./test/invariant/scripts/regression_generator.py $(file)
gen-regression-all:; ./test/invariant/scripts/gen_regression_all.py
overnight         :
	make clean; make build; \
	while true; do \
		time $(MAKE) invariant-nc; \
		sleep 10; \
	done
