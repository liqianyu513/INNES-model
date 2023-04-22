import plotting as p

with open('./results/Chainpattern.txt', encoding='utf-8') as file:
    contenders = file.read()

pattern = contenders.split("'learner':")
handle_result = ""
for i in pattern:
    tmp = i.split("'trained_on': ")
    if len(tmp) > 1:
        tmp_result = "'trained_on': " + tmp[1]
    else:
        tmp_result = tmp[0]
    handle_result += tmp_result

contenders = [eval(handle_result)]

# contenders = eval(handle_result)
#contenders = [eval(contenders)]

# print(contenders)
# f =open("C:/Users/User/Desktop/AP/results/output.txt","w")
# f.write(str(contenders))
# p.plot_averaged_episode_rewards(title=f'n1', learning_results=contenders)
p.plot_episodes_length(title=f'n1', learning_results=contenders)
# p.plot_averaged_cummulative_rewards(
#     title=f'n1',
#     all_runs=contenders)       # step-cumulative reward
# for r in contenders:
#     p.plot_all_episodes(r)  # step-cumulative reward